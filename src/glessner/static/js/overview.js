// The Case overview: the page a case opens on, and the path's first step. Where to start, from tool
// output, rules, and clock checks only; the analyst's progress, from the journal; what the case holds, and its gaps;
// and its integrity. /api/overview computes it (overview.py); a number that stands for events opens them.

import { showAudit } from './audit.js';
import { $, api, el, fmtUs, plural, post, S, setStatus } from './core.js';
import { animateView } from './data.js';
import { draw } from './draw.js';
import { button, claimDetails, headCopy, loadDetails, setPage, showingPage } from './event_page.js';
import { filterParam } from './filters.js';
import { refreshCaseState, showTab } from './frame.js';
import { openHost } from './hosts.js';
import { jumpTo, markableList, stickUnder } from './pages.js';
import { searchTerm, typedSearch } from './search.js';
import { shownCounted, sourcesOn } from './state_line.js';
import { showSuggestions } from './suggestions.js';
import { showTools } from './tools.js';
import { replaceView } from './view.js';

const LEADS_SHOWN = 8;   // the rest behind Show all, so the first screen stays a place to start
const MARKS = ['Malicious', 'Suspicious', 'Authorized'];
let showAll = false;
let turn = 0;

export async function showOverview() {
  const mine = ++turn;
  const box = $('overview');
  if (!box.firstChild) box.replaceChildren(el('p', { class: 'muted' }, 'Reading the case...'));
  refreshCaseState();   // the header's line reads the same evidence checks as Integrity
  let res;
  try { res = await api('/api/overview'); } catch (err) {
    if (mine === turn) box.replaceChildren(el('p', {}, `The overview didn't load: ${err.message}`));
    return;
  }
  if (mine !== turn) return;
  S.overview = res;
  const top = box.scrollTop;
  box.replaceChildren(el('div', { class: 'ov-grid' }, startHere(res), progress(res), holds(res)));
  box.scrollTop = top;
}

const when = (us) => (us == null ? '' : fmtUs(us).slice(0, 19));
const num = (n, action, title) => button(n.toLocaleString(), action, { class: 'linklike num', title });

// A View of exactly these marks and values, on the timeline: what a number that stands for events opens, with the same
// events listed in the Details panel under `title`, to tick and mark. The state line shows the View, with Show
// to turn it off. The Sources stay, so the status says how many of its events they hide.
// The list is asked under the filter registered for this View. /api/view_events reads only a filter's View part, so a
// later change that keeps the View, such as a Sources box, leaves the list the set the number stands for. A later change
// that replaces the View, or a failed registration, leaves nothing to list. The status counts under the filter in force,
// so it is set only when that filter is this View's. The number claims the Details panel when clicked, so a page the
// analyst asks for while the View registers and draws keeps the panel, and the list isn't asked for.
async function openView(marks, values, title) {
  showTab('timeline');
  const latest = claimDetails();
  const applying = replaceView(marks, values);
  const spec = S.viewSpec;   // set at the call; the filter's registration follows
  const { id, applied } = await applying;
  if (!id || S.viewSpec !== spec) return;
  await listOpened(title, id, latest);
  if (!applied || !sourcesOn()) return;
  await shownCounted();
  const hidden = S.viewShown == null || S.lanesShown == null ? null : S.viewShown - S.lanesShown;
  if (hidden) {
    setStatus(`The Sources hide ${plural(hidden, 'event')} this View shows; the Show beside "Hidden by Sources" on the ` +
              'state line shows them.');
  }
}

// The events a number opened, in the Details panel as a search's matches are: a tick for each, and the mark buttons,
// so they can be reviewed and triaged where they were clicked into. The ticks start over for another number.
// `filterId` is the filter registered for the number's View, and `latest` checks the claim on the panel made when the
// number was clicked or the list asked to draw again.
const opened = { key: '', checked: new Set() };

async function listOpened(title, filterId, latest) {
  if (!latest()) return;
  const key = `opened:${title}`;
  if (opened.key !== key) { opened.key = key; opened.checked = new Set(); }
  let res;
  try { res = await api(`/api/view_events?filter=${filterId}`); }
  catch (err) { setStatus(`The events didn't load: ${err.message}`); return; }
  if (!latest()) return;
  const reopen = () => listOpened(title, filterId, claimDetails());
  const render = () => {
    const { buttons, list } = markableList(res.events, opened.checked, render, () => (showingPage(key) ? reopen() : null));
    const head = el('div', { class: 'sticky-head' }, el('h2', {}, title),
      el('div', { class: 'actions' }, el('strong', {}, plural(res.total, 'event')), ...(res.total ? buttons : [])));
    stickUnder(list, head);
    setPage('opened', [el('div', { class: 'related' }, head,
      ...(res.limited ? [el('p', { class: 'muted' }, `Listing the first ${res.events.length.toLocaleString()} in time order. ` +
                                                    'The timeline shows all of them.')] : []),
      res.total ? list : el('p', {}, 'No event is in this set now.'))], { key, title, reopen });
  };
  render();
}

function startHere(res) {
  const leads = showAll ? res.leads : res.leads.slice(0, LEADS_SHOWN);
  const more = res.leads.length > LEADS_SHOWN
    ? [button(showAll ? `Show the first ${LEADS_SHOWN}` : `Show all ${res.leads.length} leads`,
              () => { showAll = !showAll; showOverview(); }, { class: 'linklike' })] : [];
  return el('section', { id: 'ovStart', 'aria-labelledby': 'ovStartHead' }, el('h2', { id: 'ovStartHead' }, 'Start here'),
    el('div', { id: 'ovLeads' }, ...(leads.length ? leads.map(leadRow)
      : [el('p', { class: 'muted' }, 'No leads: no alert with a time at medium level or above, no rule that suggests an ' +
                                     'event, and no host clock the check measured off the capture.')])),
    ...more, el('p', { class: 'ov-note' }, res.ranking));
}

function leadRow(lead) {
  const actions = {
    timeline: ['Open on timeline', () => openLead(lead), 'Open the timeline at this lead and select its events'],
    suggestions: ['Review suggestions', () => { showTab('timeline'); showSuggestions(lead.rule); }, "Open this rule's suggestions"],
    hosts: ['Show in Hosts', () => { showTab('timeline'); openHost(lead.host); }, `Open ${lead.host} in the Hosts panel`],
  };
  const [label, action, title] = actions[lead.action];
  const counts = lead.kind === 'clock' ? [] : [el('div', { class: 'counts' }, `${plural(lead.count, 'event')}; ` +
    (lead.open ? `${lead.open.toLocaleString()} without a mark or a decision` : 'each has a mark or a decision'))];
  return el('div', { class: `ov-lead${lead.worked ? ' worked' : ''}`, 'data-lead': lead.id },
    el('div', { class: `bar ${lead.level}`, title: lead.level }),
    el('div', {},
      el('div', { class: 't' }, lead.title, ...(lead.worked ? [el('span', { class: 'ov-badge' }, 'Worked')] : [])),
      el('div', { class: 'why' }, ...whyLine(lead)), ...counts,
      el('div', {}, ...lead.chips.map((c) => el('span', { class: 'ov-chip' }, c)))),
    button(label, action, { class: 'linklike go', title }));
}

// The lead's "why" line. A Hayabusa lead names its rules, and each title opens the events the rule hit on the lead's host in
// a search, at any time; the text reads as the server's `why` does. A title holding a quote can't be written as
// rule:"..." and stays text.
function whyLine(lead) {
  if (!lead.rules) return [lead.why];
  const link = (rule) => (rule.title.includes('"') ? el('span', {}, rule.title)
    : button(rule.title, () => { showTab('timeline'); typedSearch(`rule:"${rule.title}" ${searchTerm('host', lead.host)}`); },
             { class: 'linklike', title: `Search the events this rule hit on ${lead.host}, at any time` }));
  return ['Rules: ', ...lead.rules.flatMap((rule, i) => [i ? ', ' : '', link(rule), ` (${plural(rule.count, 'event')})`]),
          `${lead.rules_more ? `, and ${lead.rules_more.toLocaleString()} more` : ''}.`];
}

// Open on timeline: the lead's window with a margin, and its events selected, the earliest on the Event page; with
// several, the verdict zone lists them with their marks.
async function openLead(lead) {
  let res;
  try {
    res = await api(`/api/lead_events?tool=${encodeURIComponent(lead.tool)}&host=${encodeURIComponent(lead.host)}` +
                    `&start=${lead.start}&end=${lead.end}${filterParam()}`);
  } catch (err) { setStatus(`The lead's events didn't load: ${err.message}`); return; }
  const uids = res.uids;
  showTab('timeline');
  S.selected = new Set(uids);
  S.focus = uids[0] || null;
  S.windowLinks = [];
  draw();
  if (S.focus) loadDetails(S.focus, lead.start);
  const pad = Math.max((lead.end - lead.start) / 1000 * 0.1, 60_000);
  await animateView(lead.start / 1000 - pad, lead.end / 1000 + pad);
  // Events the Sources or the View hide are selected but not drawn, so the status says how many, and where to show them
  const hidden = [res.hidden_sources ? `${res.hidden_sources.toLocaleString()} by the Sources` : '',
                  res.hidden_view ? `${res.hidden_view.toLocaleString()} by the View` : ''].filter(Boolean);
  setStatus(`Selected the ${plural(uids.length, 'event')} of the lead: ${lead.title}` + (hidden.length
    ? `. Hidden from the timeline: ${hidden.join(' and ')}; the state line's Show buttons show them.` : ''));
}

function progress(res) {
  const p = res.progress;
  // The bar shows the marks on events in the case; the counts beside it include a mark whose event is gone
  const bar = el('div', { class: 'ov-markbar', role: 'img', 'aria-label': MARKS.map((m) => `${m} ${p.in_case[m]}`).join(', ') },
    ...MARKS.filter((m) => p.in_case[m]).map((m) => el('span', { class: m.toLowerCase(), style: `flex: ${p.in_case[m]}` })));
  const legend = el('div', { class: 'ov-legend' }, ...MARKS.map((m) => el('span', {}, el('i', { class: `ov-dot ${m.toLowerCase()}` }),
    `${m} `, num(p.marks[m], () => openView([m], [], `Events marked ${m}`), `Show the events marked ${m} on the timeline`))));
  const investigate = () => showTab('investigate');
  const last = p.last;
  const stats = el('div', { class: 'ov-stats', id: 'ovStats' },
    el('div', {}, 'Leads worked'), el('div', {}, `${p.leads_worked.toLocaleString()} of ${p.leads.toLocaleString()}`),
    el('div', {}, 'Suggestions'),
    el('div', { title: 'Events with a suggestion: decided when marked or when every suggestion on it is rejected' },
       `${p.decided.toLocaleString()} decided, `, num(p.pending, investigate, 'Open To investigate, which lists them by source'), ' pending'),
    // Three fixed relations, which the overview can count in one pass; To investigate counts each event's own top pivots, so
    // its list can show unreviewed events this number does not (and the label says which relations this one reads)
    el('div', {}, 'Marked events sharing a logon session, file, or source IP with unreviewed events'),
    el('div', {}, num(p.unreviewed_nearby, investigate, "Open To investigate, which lists the marked events. Its counts follow each event's own top pivots, so they can differ from this number"),
       ` of ${p.flagged.toLocaleString()} marked Malicious or Suspicious`),
    el('div', {}, 'Notes'), el('div', {}, num(p.notes, () => showAudit({ kind: 'Notes' }), 'Open the notes in the audit trail')),
    el('div', {}, 'Your last action'),
    el('div', {}, last ? button(`${last.at.slice(0, 19).replace('T', ' ')} UTC, ${last.who}: ${last.text}`, () => showAudit(),
                                { class: 'linklike', title: "The journal's newest entry by a person, not the app. Open the audit trail" })
      : 'none'));
  const orphans = p.orphans ? [el('p', { class: 'ov-note' }, `${plural(p.orphans, 'mark')} ${p.orphans === 1 ? 'is' : 'are'} on events ` +
                                  'no longer in the case; the counts include them, the bar and the hosts do not.')] : [];
  // IDs a case format upgrade couldn't place on one event: each stays as written, and each event it may
  // have meant says so on its Event page
  const unplaced = p.unplaced ? [el('p', { class: 'ov-note', id: 'ovUnplaced' },
    `${plural(p.unplaced, 'event ID')} the journal named before a case format upgrade could each mean more than one ` +
    'event, so entries under them stay as written; the Event page of each event it may have meant says so.')] : [];
  return el('section', { id: 'ovProgress' }, el('h2', {}, 'Your progress'),
    el('div', {}, `${plural(p.marked, 'event')} marked`), bar, legend, ...orphans, ...unplaced, stats,
    el('h3', {}, 'By host'), byHost(res.by_host));
}

function byHost(rows) {
  const marks = (host) => MARKS.map((m) => ({ host, mark: m }));
  const pending = (host) => ['malicious', 'suspicious', 'authorized'].map((v) => ({ host, mark: `Suggested: ${v}` }));
  return el('table', { class: 'ov-table', id: 'ovByHost' },
    el('thead', {}, el('tr', {}, el('th', {}, 'Host'), el('th', { class: 'num' }, 'Marks'), el('th', { class: 'num' }, 'Pending'),
                       el('th', {}, 'Leads'))),
    el('tbody', {}, ...rows.map((r) => el('tr', { 'data-host': r.host }, el('td', {}, r.host),
      el('td', { class: 'num' }, r.marks ? num(r.marks, () => openView([], marks(r.host), `${r.host}: marked events`), `Show ${r.host}'s marked events`) : '0'),
      el('td', { class: 'num' }, r.pending ? num(r.pending, () => openView([], pending(r.host), `${r.host}: events with a pending suggestion`),
                                                 `Show ${r.host}'s events with a pending suggestion`) : '0'),
      el('td', {}, r.leads ? `${r.leads_worked} of ${r.leads} worked` : 'none')))));
}

function holds(res) {
  const rows = res.hosts.map((h) => el('tr', { 'data-host': h.host },
    el('td', {}, h.host),
    el('td', {}, `${h.role}${h.guessed ? ' (guessed)' : ''}`),
    el('td', {}, h.os || 'Not recorded'),
    el('td', { class: 'num' }, h.events ? num(h.events, () => openView([], [{ host: h.host }], `${h.host}: all events`), `Show ${h.host}'s events on the timeline`) : '0',
       ...(h.untimed ? [el('div', { class: 'muted' }, `and ${h.untimed.toLocaleString()} without a time`)] : [])),
    el('td', {}, h.first == null ? '' : `${when(h.first)} to ${when(h.last)}`),
    el('td', { title: h.kinds.map((k) => `${k.label}: ${plural(k.events, 'event')}`).join('\n') }, evidence(h)),
    el('td', { class: h.clock.flag ? 'flag' : '', title: h.clock.reason }, h.clock.text),
    el('td', {}, h.review.length ? el('ul', {}, ...h.review.map((r) => el('li', {}, r))) : 'none')));
  return el('section', { class: 'span2', id: 'ovHolds' }, el('h2', {}, 'What the case holds'),
    el('table', { class: 'ov-table', id: 'ovHosts' },
      el('thead', {}, el('tr', {}, ...['Host', 'Role', 'OS', 'Events', 'First to last (UTC)', 'Evidence loaded', 'Clock', 'Needs review']
        .map((t) => el('th', { class: t === 'Events' ? 'num' : '' }, t)))),
      el('tbody', {}, ...rows)),
    el('div', { class: 'ov-grid' },
      el('div', { id: 'ovGaps' }, el('h3', {}, 'Gaps'), gaps(res.gaps)),
      el('div', { id: 'ovIntegrity' }, el('h3', {}, 'Integrity'), integrity(res.integrity))));
}

// The kinds of evidence a host's lane holds, and its events with a Hayabusa hit, counted by the lane of the event each
// hit matched (overview._hosts). A host that holds Hayabusa rows and no events says so.
function evidence(h) {
  const parts = [h.kinds.map((k) => k.label).join(', ')];
  if (h.hits) parts.push(`Hayabusa: ${plural(h.hits, 'event')} with a hit`);
  if (!h.events && !h.untimed && h.hit_rows) parts.push(`${plural(h.hit_rows, 'Hayabusa hit row')}; no events in this lane`);
  return parts.filter(Boolean).join('; ');
}

const SHOWN_UNREADABLE = 10;

// The first entries of a list of manifest entries, each path with its error, and how many more there are
function errorList(entries) {
  return el('ul', {}, ...entries.slice(0, SHOWN_UNREADABLE).map((f) => el('li', {}, `${f.path}: ${f.error}`)),
    ...(entries.length > SHOWN_UNREADABLE
      ? [el('li', {}, `and ${(entries.length - SHOWN_UNREADABLE).toLocaleString()} more`)] : []));
}

// Only what the case records: runs that failed or loaded nothing, files intake couldn't identify or read, folders it
// couldn't list, log clears, and hosts without event logs.
function gaps(g) {
  const items = [
    ...g.runs.map((r) => el('li', { 'data-run': r.run_id }, el('span', { class: 'warn' }, `${r.name} on ${r.host || 'no host'}:`),
      r.status === 'failed' ? ` failed${r.reason ? `: ${r.reason}` : ''}. ` : ` ran and loaded nothing${r.reason ? `. ${r.reason}` : ''}. `,
      button('See the run', () => { showTab('timeline'); showTools(false, { run: r.run_id }); }, { class: 'linklike' }))),
    ...(g.unidentified ? [el('li', {}, el('span', { class: 'warn' }, `${plural(g.unidentified, 'file')} intake could not identify,`),
      ' kept in the manifest and hashed. ',
      button('See in Tools', () => { showTab('timeline'); showTools(false, { unidentified: true }); }, { class: 'linklike' }))] : []),
    // Kept in the manifest with intake's error and no hash, so no check can say they match (intake._entry)
    ...(g.unreadable.length ? [el('li', { id: 'ovUnreadable' },
      el('span', { class: 'warn' }, `${plural(g.unreadable.length, 'evidence file')} intake could not read,`),
      ' so not hashed:', errorList(g.unreadable))] : []),
    // A folder's own entry, with no file of it in the manifest, so it is counted as a folder: how many files it held is
    // unknown (intake._unlisted)
    ...(g.unlisted.length ? [el('li', { id: 'ovUnlisted' },
      el('span', { class: 'warn' }, `${plural(g.unlisted.length, 'folder')} intake could not list,`),
      ` so the files ${g.unlisted.length === 1 ? 'it' : 'they'} held were not hashed:`,
      errorList(g.unlisted.map((f) => ({ ...f, path: f.path === '.' ? 'the evidence folder' : f.path }))))] : []),
    ...g.clears.map((c) => el('li', { 'data-clear': c.uid }, el('span', { class: 'warn' }, `${c.host}:`),
      ` ${c.code} in ${c.channel} at ${when(c.ts)} UTC: "${c.msg}" `,
      button('Open the event', () => { showTab('timeline'); jumpTo({ uid: c.uid, ts: c.ts }); }, { class: 'linklike' }))),
    ...(g.no_event_logs.length ? [el('li', {}, el('span', { class: 'warn' }, `${g.no_event_logs.join(', ')}:`),
      ' no event logs loaded.')] : []),
  ];
  return items.length ? el('ul', { class: 'ov-gaps' }, ...items)
    : el('p', { class: 'muted' }, "None recorded: no tool's latest run failed or loaded nothing, intake identified and read " +
                                  'every file and listed every folder, no log clear is recorded, and every host but a ' +
                                  'network sensor lane has event logs.');
}

// What each full re-hash is called, by the reason verify records (intake.FULL_CHECKS)
const FULL_REASONS = { 'case close': "at the case's close", 'full check when writing the report': 'for the report',
                       'full check when writing the findings summary': 'for the findings summary',
                       'manual full verification': 'by the verify command' };

// A file intake couldn't read stays unverified once it can be read, as it has no intake hash, and so do the files of a
// folder it couldn't list, so with either in the case the match is of the files with an intake hash, not of every
// readable one
function integrity(i) {
  const full = i.last_full;
  const matched = i.unreadable || i.unlisted ? 'every file with an intake hash matched' : 'every readable file matched';
  const rehash = full ? `${full.at.slice(0, 10)}, ${FULL_REASONS[full.reason] || full.reason}: ` +
    (full.result === 'ok' ? matched : plural(full.problems, 'problem')) : 'none yet';
  const field = (label, value, attrs = {}) => el('span', attrs, `${label}: `, el('b', {}, value));
  // Problems found since the last full re-hash that matched, which a later run's check can't clear. A file a check
  // couldn't read had no hash compared, so it is counted apart from a changed one; with both, the date is the newest's.
  const listed = i.problems.join('\n');
  const found = [
    ...(i.changed_files ? [el('span', { class: 'warn', id: 'ovChanged', title: listed },
      `Changed since intake: ${plural(i.changed_files, 'file')}`)] : []),
    ...(i.not_reread ? [el('span', { class: 'warn', id: 'ovNotReread', title: 'A check could not read ' +
      `${i.not_reread === 1 ? 'this file' : 'these files'}, as when another program holds one open, so it compared no ` +
      `hash. A full re-hash that matches, such as the verify command's, clears this.\n${listed}` },
      `Could not be re-read, so not compared with intake: ${plural(i.not_reread, 'file')}`)] : []),
  ];
  if (found.length) {
    found.at(-1).append(`${found.length > 1 ? '; the newest' : ','} found by the check of ${i.found_at.slice(0, 10)}`);
  }
  // A line of the check log that isn't a check, such as the 0x00 a crash during a write leaves, may have held a problem
  const lines = i.unreadable_lines ? [el('span', { class: 'warn', id: 'ovCheckLines' },
    `${plural(i.unreadable_lines, 'line')} of verification.jsonl could not be read, so any problem ` +
    `${i.unreadable_lines === 1 ? 'it holds' : 'they hold'} is not counted here`)] : [];
  return el('div', { class: 'ov-integrity' },
    el('span', {}, el('b', {}, i.evidence_files.toLocaleString()), ` evidence ${i.evidence_files === 1 ? 'file' : 'files'} hashed at intake (${i.algorithm})` +
       (i.added_files ? `, and ${i.added_files.toLocaleString()} added later` : '') +
       (i.unreadable ? `; ${i.unreadable.toLocaleString()} could not be read` : '') +
       (i.unlisted ? `; ${plural(i.unlisted, 'folder')} could not be listed` : '')),
    ...found, ...lines, field('Last full re-hash', rehash, { id: 'ovRehash' }),
    i.journal ? journalRow(i.journal) : field('Journal', plural(i.journal_entries, 'entry', 'entries')),
    field('Times shown', i.times), field('Build', i.build));
}

// Integrity's Journal row: whether the chain is consistent, in the words that say which
// head outside the case it was compared with, never "intact"; the head, short, with Copy; Check now, a full check that
// writes nothing; and on a break, Continue with the break on record, which asks for a reason first.
function journalRow(j) {
  const reason = el('div', { class: 'journal-continue', hidden: '' });
  const check = button('Check now', async () => {
    try { await post('/api/journal_check', {}); } catch (err) { setStatus(`The journal check failed: ${err.message}`); return; }
    refreshCaseState();
    showOverview();
  }, { title: 'Check every line of the journal again, from the first. Writes nothing.' });
  const actions = [check];
  if (j.can_continue) {
    actions.push(button('Continue with the break on record...', () => {
      const text = el('textarea', { rows: 2, class: 'mark-note', 'aria-label': 'Reason',
                                    placeholder: 'Why the case continues, such as what you found about the change' });
      const go = button('Continue', async () => {
        if (!text.value.trim()) { setStatus('Give a reason first: it is kept in the journal with the break.'); return; }
        let res;
        try { res = await post('/api/chain_break', { reason: text.value }); }
        catch (err) { setStatus(`Continuing failed: ${err.message}`); return; }
        setStatus(`The break is on record as entry #${res.seq}. The case takes changes again.`);
        refreshCaseState();
        showOverview();
      }, { class: 'primary' });
      reason.replaceChildren(
        el('p', { class: 'muted' }, 'This adds an entry that lists the breaks, seals every line before it, and keeps your ' +
           'reason. Nothing is repaired: verify reports the break and this entry for the life of the case.'),
        text, el('div', { class: 'actions' }, go, button('Cancel', () => { reason.hidden = true; })));
      reason.hidden = false;
      text.focus();
    }, { class: 'undo' }));
  }
  return el('div', { id: 'ovJournal', class: `ov-journal ${j.state}` },
    el('span', {}, 'Journal: ', el('b', { class: j.state === 'broken' ? 'warn' : '' }, j.text[0]), ' ', j.text.slice(1).join(' ')),
    el('span', {}, 'Head ', ...headCopy(j.head, j.short), j.seq != null ? ` (entry #${j.seq})` : ''),
    el('span', { class: 'actions' }, ...actions), reason);
}
