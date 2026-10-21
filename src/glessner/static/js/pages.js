import { askGroupDecision, markWord } from './confirm.js';
import { $, api, codePrefix, el, fmtAt, fmtGap, fmtUs, gapTitle, markBadge, markState, PIVOT_LABELS, plural, post, reportAction, RULE_TEMPLATE, S, setStatus } from './core.js';
import { refreshCounts } from './counts.js';
import { animateView, fetchView } from './data.js';
import { draw } from './draw.js';
import { applyMark, button, claimDetails, decide, loadDetails, readOnlyHint, refreshTrail, setPage, shownAt, showingPage } from './event_page.js';
import { filterParam } from './filters.js';
import { reloadLanes } from './lanes.js';
import { rowQuery } from './pivots.js';
import { startReview } from './review.js';
import { showSuggestions } from './suggestions.js';
import { openTagPicker } from './tags.js';
import { trailPivot } from './trail.js';
import { describeValue, setFaded, viewToggle } from './view.js';

// ---------- To investigate: the worklist ----------
// Two sections, each with a progress meter: the Malicious and Suspicious events, with a Followed up tick the analyst sets
// (journaled through /api/followup, kept when the mark changes later) and, beside each, the top three
// countable pivots of its kind's ranking (pivots.worklist_rows) counted as unreviewed events once the page has drawn, each
// count a link that opens the event's page with that pivot kept to unreviewed events, so the list's total is the count;
// and the pending suggestions by rule, each with why it fired, its progress, Review one by
// one, and Accept all and Reject all, which ask first. Evidence text reaches the page through el() only.

let counting = null;              // the counts of the page drawn last; the next page ends them
const countCache = new Map();     // uid and row key to count, kept while the page redraws after a tick
const COUNT_POOL = 4;             // counts in flight at once, so the timeline's own requests still get through

export async function showInvestigate({ keepCounts = false } = {}) {
  const latest = claimDetails();   // a page asked for after it keeps the panel
  let res;
  try { res = await api('/api/investigate'); } catch (err) { setStatus(err.message); return; }
  if (!latest()) return;
  if (!keepCounts) countCache.clear();
  if (counting) counting.abort();
  counting = new AbortController();
  const loadedAt = new Date();   // what the confirm names as when the page counted
  const items = res.items;
  const followed = items.filter((i) => i.followup).length;
  const refresh = (opts) => { if (showingPage('investigate')) showInvestigate(opts); };
  const pending = res.rules.filter((r) => r.pending > 0 && !r.error);
  const matched = res.rules.filter((r) => !r.error).reduce((n, r) => n + (r.matched || 0), 0);
  const decided = matched - res.rules.filter((r) => !r.error).reduce((n, r) => n + (r.pending || 0), 0);
  const head = el('div', { class: 'inv-head sticky-head' }, el('h2', {}, 'Marked events to follow up'),
                  meter(followed, items.length, 'followed up', 'nothing marked yet'));
  const list = items.length ? worklist(items, refresh) : null;
  // The find box narrows the rows shown; the list holds every marked event, so it reaches them all
  const find = list ? listFind(list, { page: 'investigate', name: 'worklist', covers: 'The meter and the counts still cover' }) : null;
  if (find) head.append(find.box);
  const nodes = [
    ...readOnlyHint(),
    el('section', { class: 'inv-section' }, head,
       list || el('p', { class: 'muted' }, 'Nothing is marked Malicious or Suspicious yet. Mark events from the timeline, a list, or a suggestion.'),
       ...(find ? [find.foot] : [])),
    el('section', { class: 'inv-section' },
       el('div', { class: 'inv-head' }, el('h2', {}, 'Pending suggestions, by rule'), meter(decided, matched, 'decided', 'nothing suggested yet')),
       ...(pending.length ? pending.map((r) => ruleRow(r, loadedAt, refresh))
         : [el('p', { class: 'muted' }, matched ? 'Every suggestion is decided.' : 'No rule or tool has suggested a mark yet.')]),
       el('p', { class: 'muted inv-foot' }, 'Review one by one opens each pending event on the Event page with Accept, Reject, and a note: ' +
          'A accepts, R rejects, N goes to the next. Accept all and Reject all ask first.')),
  ];
  setPage('investigate', nodes, { title: 'To investigate', reopen: showInvestigate });
  if (list) {
    stickUnder(list, head);
    askCounts(items, counting.signal);
  }
}

// A progress meter on the start page's pattern (a --d5 bar on a --bg track), with its count in words beside it
function meter(done, total, what, none) {
  const bar = el('div', { class: 'bar' });
  bar.style.width = `${total ? Math.round((done / total) * 100) : 0}%`;   // a size, which the CSP allows a script to set
  const words = total ? `${done.toLocaleString()} of ${total.toLocaleString()} ${what}` : none;
  return el('span', { class: 'meter', role: 'img', 'aria-label': words }, el('span', { class: 'progress' }, bar), el('span', { class: 'meter-words' }, words));
}

// The marked events as a grid under a sticky Mark heading: Done, the badge, time, host, the event with its note and its
// Followed up line, and what is still unreviewed around it (the counts, filled in by askCounts)
function worklist(items, refresh) {
  const cell = (cls, ...nodes) => el('span', { class: cls }, ...nodes);
  const head = el('li', { class: 'rel-head', 'aria-hidden': 'true' },
    cell('inv-done', 'Done'), cell('rel-mark', 'Mark'), cell('rel-time', 'Time (UTC)'), cell('rel-host', 'Host'),
    cell('rel-event', 'Event'), cell('inv-counts', 'Still unreviewed around it'));
  head.querySelector('.inv-done').title = 'Followed up: your own tick, journaled with who and when';
  head.querySelector('.rel-mark').title = 'Review state: S suspicious, M malicious';
  head.querySelector('.inv-counts').title = 'Unreviewed events the event\'s top pivots reach. A count opens that list.';
  const rows = items.map((item) => {
    const tick = el('input', { type: 'checkbox', class: 'inv-tick', 'aria-label': `Followed up: the ${item.host} event at ${item.ts == null ? 'no time' : fmtUs(item.ts).slice(11, 19)}` });
    tick.checked = !!item.followup;
    tick.addEventListener('change', () => followUp(item, tick.checked, refresh));
    const lines = [withTitle(el('span', { class: 'rel-text' }, `${codePrefix(item)}${item.msg}`))];
    if (item.note) lines.push(el('div', { class: 'muted inv-note' }, `Note: ${item.note}`));
    if (item.followup) lines.push(followedLine(item));
    const counts = el('span', { class: 'inv-counts' }, ...item.rows.map((row) => countNode(item, row)));
    if (!item.rows.length) counts.append(el('span', { class: 'muted' }, 'no countable pivot for this kind of event'));
    // A click anywhere on the row but its controls opens the event
    return el('li', { class: `rel-row${item.followup ? ' done' : ''}`, 'data-uid': item.uid,
                      onclick: (ev) => { if (!ev.target.closest('input, button')) jumpTo(item); } },
      tick, markBadge(item), cell('rel-time', fmtUs(item.ts)), el('span', { class: 'rel-host', title: item.host }, item.host),
      el('span', { class: 'rel-event' }, ...lines), counts);
  });
  return el('ul', { class: 'rows no-off worklist' }, head, ...rows);
}

// "Followed up 22:40 by cody" under the event, the full time and the entry in its hover; when the mark changed after the
// tick, the line says so
function followedLine(item) {
  const f = item.followup;
  const when = fmtAt(f.at);
  let text = `Followed up ${when.slice(11, 16)} by ${f.who}`;
  let title = `Followed up ${when} by ${f.who} (entry #${f.seq})`;
  if (f.after_mark) {
    const since = item.mark_at ? ` at ${fmtAt(item.mark_at).slice(11, 16)}` : '';
    text += `; marked ${item.mark}${since}, after the tick`;
    title += `. The mark changed to ${item.mark}${item.mark_at ? ` at ${fmtAt(item.mark_at)}` : ''}, after the tick, which stays.`;
  }
  return el('div', { class: 'muted inv-followed', title }, text);
}

async function followUp(item, done, refresh) {
  try {
    const res = await post('/api/followup', { uids: [item.uid], done });
    reportAction(done ? 'Marked one event followed up' : 'Cleared Followed up on one event', res.server_ms);
    refresh({ keepCounts: true });   // the counts have not changed; the row's line and the meter have
  } catch (err) { setStatus(`Follow-up failed: ${err.message}`); refresh({ keepCounts: true }); }
}

// One count beside an event: its pivot's label, then "…" until counted, a blue count that opens the list, or 0 as text
function countNode(item, row) {
  const node = el('span', { class: 'inv-count', 'data-pivot': row.pivot, 'data-key': row.key });
  const label = row.pivot === 'window' ? row.label.replace(/ ±N s$/, ` ±${row.seconds} s`) : row.label;
  const value = row.pivot === 'addr' ? ` ${row.ip}` : '';
  node.append(el('span', { class: 'inv-count-label', title: row.reason }, `${label}${value}`), ' ');
  const cached = countCache.get(`${item.uid}\n${row.key}`);
  node.append(cached == null ? el('span', { class: 'muted inv-n' }, '…') : countResult(item, row, cached));
  return node;
}

function countResult(item, row, count) {
  if (!count) return el('span', { class: 'muted inv-n', title: 'No unreviewed event there' }, '0');
  return el('button', { type: 'button', class: 'linklike inv-n', title: `Open the ${plural(count, 'unreviewed event')} of ${row.label}`,
                        onclick: () => openCount(item, row) }, count.toLocaleString());
}

// Count each row as unreviewed events, a few at a time, after the page has drawn. The page records when the last count
// drew and the slowest count in window.__timings, for timing measurements.
async function askCounts(items, signal) {
  const jobs = items.flatMap((item) => item.rows.filter((row) => !countCache.has(`${item.uid}\n${row.key}`)).map((row) => [item, row]));
  const started = performance.now();
  let slowest = 0;
  const one = async ([item, row]) => {
    const t0 = performance.now();
    let count = null, why = '';
    try { count = (await api(`/api/pivot_count?${rowQuery(item.uid, item.ts, row, { unreviewed: 1 })}`, { signal })).count; }
    catch (err) { if (err.name === 'AbortError' || signal.aborted) return; why = err.message; }
    slowest = Math.max(slowest, performance.now() - t0);
    if (count != null) countCache.set(`${item.uid}\n${row.key}`, count);
    const node = $('detailsBody').querySelector(`li[data-uid="${item.uid}"] .inv-count[data-key="${CSS.escape(row.key)}"] .inv-n`);
    if (!node) return;
    node.replaceWith(count != null ? countResult(item, row, count) : el('span', { class: 'muted inv-n', title: why }, 'could not count'));
  };
  let next = 0;
  const worker = async () => { while (next < jobs.length && !signal.aborted) await one(jobs[next++]); };
  await Promise.all(Array.from({ length: Math.min(COUNT_POOL, jobs.length) }, worker));
  if (!signal.aborted) window.__timings.push({ page: 'investigate', counts: jobs.length, ms: performance.now() - started, slowest_ms: slowest });
}

// A count's click: the event's page, then its pivot kept to unreviewed events, whose total is the count
async function openCount(item, row) {
  await jumpTo(item);
  await pivot(item.uid, row.pivot, row.seconds, row.ip || null,
              { label: row.label, ...(row.name ? { name: row.name } : {}), unreviewed: true });
}

// One suggestion source with pending suggestions: its name (a link to its Suggestions page), who added it, why it fired,
// its progress, and its actions. Accept all and Reject all ask first, in the row.
function ruleRow(r, loadedAt, refresh) {
  const row = el('div', { class: 'rule', 'data-source': r.id });
  const act = async (decision) => {
    const uids = await askGroupDecision({ decision, source: r.id, value: r.suggest, uids: r.uids || [], listed: 0, first: r.first || [],
                                          loadedAt, showAll: () => showSuggestions(r.id, '', r.pending), host: row });
    if (!uids) return;
    await decide(decision, r.id, uids, { confirmed: { count: uids.length }, fromEvent: false });
    refresh();   // the page then lists what is left, unless another page was asked for meanwhile
  };
  const done = (r.matched || 0) - r.pending;
  const description = String(r.description || '').split(/\s+/).join(' ');
  row.append(
    el('div', { class: 'rule-what' },
       button(r.id, () => showSuggestions(r.id), { class: 'linklike rule-name', title: `Open ${r.id}'s Suggestions page` }),
       ' ', el('span', { class: 'muted' }, r.builtin ? '(built-in)' : `(added by ${r.who})`),
       el('div', { class: 'muted rule-why' }, 'Why it fired: ', description || `the rule ${r.id} has no description; the Rules page shows what it matches.`)),
    el('div', { class: 'rule-meter' }, meter(done, r.matched || 0, 'decided', ''),
       el('span', { class: 'muted rule-pending' }, `${plural(r.pending, 'event')} pending, would be ${markWord(r.suggest)}`)),
    el('div', { class: 'actions rule-acts' },
       button('Review one by one', () => startReview(r.id, r.suggest, r.uids || []),
              { class: 'primary', title: `Open each of the ${plural(r.pending, 'pending event')} on its Event page in turn` }),
       button('Accept all', () => act('accept'), { title: `Asks first: accept the ${plural(r.pending, 'event')} counted when the page loaded` }),
       button('Reject all', () => act('reject'), { title: 'Asks first: reject them, which leaves them unreviewed' })));
  return row;
}

export async function showRules() {
  const latest = claimDetails();
  let res;
  try { res = await api('/api/rules'); } catch (err) { setStatus(err.message); return; }
  if (!latest()) return;
  const editor = el('textarea', { rows: '9', cols: '90', spellcheck: 'false' });
  editor.value = RULE_TEMPLATE;
  const message = el('p', { class: 'muted' });
  const save = async (op) => {
    try {
      await post('/api/rule', { op, text: editor.value });
      await reloadLanes();
      await fetchView();
      if (showingPage('rules')) showRules();   // not over a page asked for meanwhile
      refreshCounts();
    }
    catch (err) { message.textContent = err.message; }
  };
  const rows = res.rules.map((r) => el('tr', {},
    el('td', {}, r.id), el('td', {}, r.error ? `Error: ${r.error}` : `suggests ${r.suggest}`),
    el('td', {}, `${r.matched.toLocaleString()} matched, ${r.pending.toLocaleString()} pending`),
    el('td', {}, r.builtin ? 'built-in' : `added by ${r.who}`),
    el('td', {}, ...(r.editable ? [
      el('button', { type: 'button', onclick: () => { editor.value = r.text; } }, 'Edit'), ' ',
      el('button', { type: 'button', onclick: async () => {
        try {
          await post('/api/rule', { op: 'remove', id: r.id });
          await reloadLanes();
          await fetchView();
          if (showingPage('rules')) showRules();
          refreshCounts();
        }
        catch (err) { message.textContent = err.message; } } }, 'Remove')] : []))));
  setPage('rules', [
    el('h2', {}, 'Suggestion rules'),
    el('p', { class: 'muted' }, 'Rules suggest a mark; you accept or reject each suggestion. Fields: any event column, ' +
       'plus account (domain\\user) and source_host. Operators: equals, in, regex, between, and collected (source_host only).'),
    el('table', {}, ...rows),
    editor,
    el('div', { class: 'actions' },
       el('button', { type: 'button', onclick: () => save('add') }, 'Add rule'),
       el('button', { type: 'button', onclick: () => save('change') }, 'Save changes to existing rule')),
    message], { title: 'Rules', reopen: showRules });
}

export async function addNote(uid, text) {
  if (!text.trim()) return;
  try { await post('/api/note', { uid, text }); loadDetails(uid); } catch (err) { setStatus(`Note failed: ${err.message}`); }
}

// A pivot draws only if it is the latest asked and the panel still shows its event's page: one that answers after the
// analyst has taken another pivot, opened another event, or asked for another page would set its list, its highlights, and
// its trail step over theirs.
let pivotTurn = 0;

// `ip` names the address for the IP pivot at either end (kind addr): one the event has. `more` narrows a
// window to one `source` of its breakdown, names its `sourceLabel`, asks for the connection's case-wide list with `scope`
// 'case', gives the row's `label`, which the trail keeps, the `name` a Same file name row fixes, and `unreviewed`, which keeps
// the list to events with no mark, as a To investigate count opens it. The list's size and the server's time are the
// status line's last action, unless the list is drawn again after a mark (`quiet`), which keeps the mark's line.
export async function pivot(uid, kind, seconds, ip = null, more = {}, quiet = false) {
  const turn = ++pivotTurn;
  const current = () => turn === pivotTurn && S.focus === uid && showingPage(`event:${uid}`);
  let res;
  try {
    const at = shownAt(uid);
    res = await api(`/api/related?uid=${encodeURIComponent(uid)}&kind=${kind}` + (seconds ? `&seconds=${seconds}` : '')
                    + (ip ? `&ip=${encodeURIComponent(ip)}` : '') + (more.source ? `&source=${encodeURIComponent(more.source)}` : '')
                    + (more.scope ? `&scope=${more.scope}` : '') + (more.name ? `&name=${encodeURIComponent(more.name)}` : '')
                    + (more.unreviewed ? '&unreviewed=1' : '')
                    + (at == null ? '' : `&ts=${at}`) + filterParam());
  } catch (err) { if (current()) $('relatedList')?.replaceChildren(el('p', {}, err.message)); return; }
  if (!current()) return;
  S.related = new Set(res.events.map((e) => e.uid));
  S.windowLinks = kind === 'window' ? res.events.map((e) => ({ uid: e.uid, gap_s: e.gap_s })) : [];
  const p = S.pivotResult;
  if (!p || p.uid !== uid || p.kind !== kind || p.ip !== ip || p.more.source !== more.source || !p.more.unreviewed !== !more.unreviewed) {
    S.pivotChecked = new Set();
  }
  const step = { type: 'pivot', uid, kind, seconds, ip, more, label: pivotStep(kind, seconds, ip, more), total: res.total ?? res.events.length };
  // Kept so the list survives the Event page re-rendering after a mark; its step lets a click on it continue the trail
  S.pivotResult = { uid, kind, seconds, ip, more, res, step };
  trailPivot(step);
  refreshTrail();
  draw();
  renderRelated();
  showList();
  if (S.viewSpec) await setFaded(res.events.map((e) => e.uid));   // shown faded where the View hides them
  if (!quiet && current()) reportAction(`${step.label}: ${plural(step.total, 'event')}`, res.server_ms);
}

// Bring the list to the top of the work column, where it sits under the pivots. Only the column scrolls, never the
// panel (scrollIntoView would move every scroller above it, and the trail with it); at a panel width where the
// body scrolls as one, the body does, below the header when that sticks (it scrolls away when it is taller than half the body).
function showList() {
  const list = $('relatedList'), work = list?.closest('.ev-work');
  if (!list || !work) return;
  const body = $('detailsBody');
  const scroller = getComputedStyle(work).overflowY === 'auto' ? work : body;
  const head = body.querySelector(':scope > .ev-head');
  const stuck = scroller === body && head && getComputedStyle(head).position === 'sticky' ? head.offsetHeight : 0;
  scroller.scrollTop += list.getBoundingClientRect().top - scroller.getBoundingClientRect().top - stuck;
}

// A pivot as the trail words it: "Same IP at either end: 10.0.4.23", "Same host within ±300 s". A list narrowed to one source
// of its row's breakdown ends ", only 7036", and one kept to unreviewed events ", unreviewed only".
const UNREVIEWED_ONLY = ', unreviewed only';
function pivotStep(kind, seconds, ip, more) {
  const name = more.label || PIVOT_LABELS[kind] || kind;
  const only = (more.sourceLabel ? `, only ${more.sourceLabel}` : '') + (more.unreviewed ? UNREVIEWED_ONLY : '');
  if (kind === 'window') return `${name.replace(/ within.*$/, '')} within ±${seconds} s${only}`;
  if (kind === 'connection' && more.scope === 'case') return `${name}, case-wide${only}`;
  return (ip ? `${name}: ${ip}` : name) + only;
}

// The value a pivot's results share, to add to the view filter from the list.
function pivotValue(kind, res) {
  const anchor = res.anchor;
  if (!anchor) return null;
  const here = res.host ? { host: res.host } : {};   // a loopback or link-local address matches on its host only
  if (kind === 'addr') return res.address ? { addr: res.address, ...here } : null;   // the address at either end
  if (kind === 'source_ip') return { ip: anchor.source_ip, ...here };
  if (kind === 'connection') return { ip: anchor.source_ip, port: anchor.source_port, ...here };
  if (kind === 'account') return { user: anchor.user_domain ? `${anchor.user_domain}\\${anchor.user_name}` : anchor.user_name };
  if (kind === 'workstation') return { workstation: anchor.source_workstation };
  return null;
}

// The heading over a pivot's results. The IP pivot at either end leads with its address. From an event
// without a time, a long list is the first in time order, not the nearest.
// A window names itself and says what the list holds, with how far the reach line says the list goes; a list
// narrowed to a source says which, ", only 7036", in every kind.
function pivotHeading(kind, res, more = {}, seconds = null) {
  const n = res.events.length, of = () => `of ${res.total.toLocaleString()} events`;
  const nearest = () => (res.nearest ? `${n} nearest ${of()}` : `first ${n} ${of()}`);
  const only = (more.sourceLabel ? `, only ${more.sourceLabel}` : '') + (res.unreviewed ? UNREVIEWED_ONLY : '');
  if (kind === 'addr' && res.address) {
    const where = res.host ? `, on ${res.host} only` : '';   // a loopback or link-local address stays on the seed's host
    return `${res.address} at either end${where}${only}: ${res.limited ? `the ${nearest()}` : plural(n, 'event')}`;
  }
  if (kind === 'window' && seconds) {
    return `Same host within ±${seconds} s${only}: ${res.limited ? `the ${nearest()}` : plural(n, 'event')}`;
  }
  return (res.limited ? `The ${nearest()} with the ${res.label}` : `${plural(n, 'event')} with the ${res.label}`) + only;
}

// What a list cut at the limit reaches in time, in a line under its heading. A window says how far from the event
// the nearest events go, against the whole window the analyst asked for, and where to find the rest: the row's breakdown
// when the click came from the row (its `rank`) and the list is not already narrowed to one source, else a smaller window.
// Any other list with times gives its signed reach, from the earliest to the latest offset it holds. Nothing for a list
// that holds everything, or has no times.
function reachLine(kind, res, more, seconds) {
  if (!res.limited || !res.nearest) return null;
  const gaps = res.events.map((e) => e.gap_s).filter((g) => g != null);
  if (!gaps.length) return null;
  if (kind !== 'window') {
    return el('p', { class: 'muted pv-reach' }, `These ${res.events.length.toLocaleString()} reach ${fmtGap(Math.min(...gaps))} to ${fmtGap(Math.max(...gaps))} around this event.`);
  }
  const rest = more.rank && !more.source ? `open one source in row ${more.rank} above` : 'make the window smaller';
  return el('p', { class: 'muted pv-reach' },
    `The ${res.events.length.toLocaleString()} nearest of ${res.total.toLocaleString()}, reaching ${fmtGap(res.reach_s, { reach: true })} of this event, ` +
    `not the whole ±${seconds} s window. For the rest, ${rest}. Hover an offset for the exact seconds.`);
}

export function renderRelated() {
  const box = $('relatedList');
  const p = S.pivotResult;
  if (!box || !p || p.uid !== S.focus) return;
  const { uid, kind, seconds, ip, res } = p;
  const more = p.more || {};
  const checked = S.pivotChecked;
  const clear = () => {
    S.related = new Set(); S.windowLinks = []; S.pivotResult = null; S.pivotChecked = new Set();
    if (S.faded.length) setFaded([]);
    draw(); box.replaceChildren(); renderRelated();
  };
  // Build the chain: tick the results that belong, mark them, and they join the View.
  // The IP pivot at either end says which end the address was on for each event.
  const column = kind === 'addr' && res.address
    ? { head: 'End', title: 'Which end of the connection held the address', value: (e) => e.end } : null;
  // The find box is kept by the pivot, so a new pivot on the page starts it empty; a cut list says how far it reaches
  const find = { page: `event:${uid}`, name: `pivot:${JSON.stringify([kind, seconds, ip, more])}`, covers: 'The heading still covers',
                 listed: res.limited ? res.events.length : null, total: res.total ?? null, more: 'events' };
  const { buttons, list, find: found } = markableList(res.events, checked, renderRelated, () => pivot(uid, kind, seconds, ip, more, true),
                                                      { column, via: true, find });
  const hidden = S.viewSpec ? res.events.filter((e) => !e.shown).length : 0;
  const value = pivotValue(kind, res);
  const header = el('div', { class: 'actions sticky-head' },   // fixed at the list's top while it scrolls
    el('strong', {}, pivotHeading(kind, res, more, seconds)),
    ...(S.viewSpec ? [el('span', { class: 'muted' }, `${hidden.toLocaleString()} hidden by the View`)] : []),
    ...buttons,
    ...(value ? [viewToggle(value, { name: describeValue(value), className: '' })] : []),
    button('Clear', clear), found.box);
  const notes = [];
  const reach = reachLine(kind, res, more, seconds);
  if (reach) notes.push(reach);
  if (res.note) notes.push(el('p', { class: 'muted' }, res.note));
  if (res.match_note) notes.push(el('p', { class: 'muted' }, res.match_note));
  // Same source IP and port is bounded to the case's window, since a port is reused; the case-wide list is a click away
  if (kind === 'connection' && res.seconds != null) {
    notes.push(el('p', { class: 'muted' }, 'Within the case time window around this event, since a source port is reused. ',
                  button('Show the case-wide list', () => pivot(uid, kind, seconds, ip, { ...more, scope: 'case' }), { class: 'linklike' })));
  }
  if (kind === 'window' && res.events.length > 40) {
    notes.push(el('p', { class: 'muted' }, 'More than 40 events in the window, so the dashed links are not drawn. Narrow the window to see them.'));
  }
  // A cut list's find line goes over the list, where its reach is read before the rows; an uncut one's under it
  box.replaceChildren(header, ...notes, ...(res.limited ? [found.foot, list] : [list, found.foot]));
  stickUnder(list, header);
}

// The note typed beside a list's mark buttons, by the list's set of ticked events, so a tick that redraws the list
// keeps it.
const listNotes = new WeakMap();

// The list's column heading sticks under the list's own head, which can wrap and so change height: the head's height is
// kept on the list as --list-head-h, which the heading's `top` reads (the CSP allows a script to set a size). One observer
// at a time, since one list is on screen.
let headWatch = null;
export function stickUnder(list, head) {
  if (headWatch) headWatch.disconnect();
  headWatch = new ResizeObserver(() => list.style.setProperty('--list-head-h', `${head.offsetHeight}px`));
  headWatch.observe(head);
}

// The whole text in the hover, for a list that cuts it to one line
const withTitle = (node) => { node.title = node.textContent; return node; };

// ---------- the find box on a list of events ----------
// One box in a list's head narrows the rows shown to those whose text holds every word of the find, in any order and any
// letter case, and marks the words in the host and event cells. Counts, meters, and headings never change with it, so a
// count still equals what its click lists. The text is kept by page and list (S.finds, which setPage starts again when
// the page's key changes), so a tick, a mark, or a count drawn later keeps it, and a new page starts empty. On a list cut
// at its limit the box says how far it reaches, and a search offers to run again with the words added. Evidence text is
// matched and marked as text nodes, never as HTML.

// The kept text of a page's list. A list is built before setPage draws its page, so the page's key is compared here too.
function findTextOf(page, name) {
  if (S.finds.key !== page) S.finds = { key: page, lists: new Map() };
  return S.finds.lists.get(name) || '';
}

// The words of a find, each as the test for a row's text and the finder for the marks; nothing for an empty find
function findWords(text) {
  return text.trim().split(/\s+/).filter(Boolean).map((word) => {
    const src = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return { word, test: new RegExp(src, 'i'), find: new RegExp(src, 'gi') };
  });
}

// Whether a find's words would mean in a search what they mean here: a bare word matches anywhere, but one that starts
// with "-" excludes, one with ":" names a field, one with a quote bounds, and one with "*" is a wildcard. Only plain words
// are offered as a search over every match.
const plainWord = (word) => !word.startsWith('-') && !/[:"*]/.test(word);

// Wrap each occurrence of the words in a cell's text nodes in a mark; the nodes are collected first, since wrapping one
// changes the tree. A word inside a search highlight is marked inside it.
function markWords(cell, words) {
  const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT);
  const nodes = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) nodes.push(n);
  for (const node of nodes) {
    const text = node.nodeValue;
    const ranges = [];
    for (const { find } of words) {
      find.lastIndex = 0;
      for (let m = find.exec(text); m && ranges.length < 200; m = find.exec(text)) {
        if (!m[0]) break;
        ranges.push([m.index, m.index + m[0].length]);
      }
    }
    if (!ranges.length) continue;
    ranges.sort((a, b) => a[0] - b[0]);
    const out = document.createDocumentFragment();
    let pos = 0;
    for (const [a, b] of ranges) {
      if (b <= pos) continue;
      const from = Math.max(a, pos);
      if (from > pos) out.append(text.slice(pos, from));
      out.append(el('mark', { class: 'find-hit' }, text.slice(from, b)));
      pos = b;
    }
    if (pos < text.length) out.append(text.slice(pos));
    node.replaceWith(out);
  }
}

// The box for `list`, whose rows match `rows`: the input, the count of rows that match, and Clear, in `box`, and the line
// for under the list, or over a cut one, in `foot`. `page` and `name` key the kept text. `cells` are the parts of a row
// the find reads, and `highlight` those it marks. `covers` begins the foot's sentence about what the find leaves whole:
// "The meter and the counts still cover". With `listed` under `total` the list is cut: the box says it reaches the listed
// rows, and `searchAll(text)`, for a search, runs it again over every match. `onApply(shown)` gets the set of the shown
// rows' data-uid, or null with no find, after each change. `shown()` gives that set at any time.
export function listFind(list, { page, name, rows = 'li.rel-row', cells = '.rel-time, .rel-host, .rel-event, .rel-col',
                                 highlight = '.rel-host, .rel-text', covers = 'The counts still cover', listed = null,
                                 total = null, more = 'matches', searchAll = null, onApply = null }) {
  const cut = listed != null && total != null && total > listed;
  const label = cut ? `Find in the ${listed.toLocaleString()} listed` : 'Find in this list';
  const input = el('input', { type: 'search', 'aria-label': label, placeholder: label, autocomplete: 'off', spellcheck: 'false',
    title: cut ? `Shows only the listed rows holding every word. It reaches the ${listed.toLocaleString()} listed, not every match.`
      : `Shows only the rows holding every word, in any column. ${covers} every row.` });
  input.value = findTextOf(page, name);
  const count = el('span', { class: 'find-words' });
  const clear = () => { input.value = ''; apply(); input.focus(); };
  const clearButton = button('Clear', clear, { class: 'linklike find-clear' });
  const box = el('span', { class: 'find' }, input, count, clearButton);
  const foot = el('p', { class: 'find-foot', hidden: '' });
  let shownNow = null;
  const rowsOf = () => [...list.querySelectorAll(rows)];
  const textOf = (row) => {
    const parts = row.querySelectorAll(cells);
    return (parts.length ? [...parts].map((c) => c.textContent) : [row.textContent]).join('\n');
  };
  const apply = () => {
    S.finds.lists.set(name, input.value);
    const words = findWords(input.value);
    for (const m of list.querySelectorAll('mark.find-hit')) m.replaceWith(...m.childNodes);
    for (const cell of list.querySelectorAll(highlight)) cell.normalize();   // split text joins again, so a word is whole
    const all = rowsOf();
    let shown = 0;
    shownNow = words.length ? new Set() : null;
    for (const row of all) {
      const hit = !words.length || words.every(({ test }) => test.test(textOf(row)));
      row.classList.toggle('find-out', !hit);
      if (!hit) continue;
      shown++;
      if (!words.length) continue;
      if (row.dataset.uid) shownNow.add(row.dataset.uid);
      for (const cell of row.querySelectorAll(highlight)) markWords(cell, words);
    }
    const n = all.length, hidden = n - shown;
    count.hidden = clearButton.hidden = !words.length;
    count.textContent = !words.length ? '' : cut ? `${shown.toLocaleString()} of the ${listed.toLocaleString()} listed match`
      : `${shown.toLocaleString()} of ${n.toLocaleString()} ${n === 1 ? 'row matches' : 'rows match'}`;
    foot.hidden = !words.length || (!cut && !hidden);
    if (cut) {
      const offer = searchAll && words.every(({ word }) => plainWord(word));   // the same words, not a different search
      foot.replaceChildren(el('span', { class: 'muted' }, `The find reaches the ${listed.toLocaleString()} listed rows only; ` +
                              `${(total - listed).toLocaleString()} more ${more} aren't listed.`),
                           ...(offer ? [' ', button(`Search all ${total.toLocaleString()} for "${input.value.trim()}"`,
                                                    () => searchAll(input.value.trim()), { class: 'linklike find-all' })] : []));
    } else {
      foot.className = 'muted find-foot';
      foot.replaceChildren(`${plural(hidden, 'row')} ${hidden === 1 ? "doesn't" : "don't"} hold every word of the find. ` +
                           `${covers} all ${n.toLocaleString()}. `, button('Clear the find', clear, { class: 'linklike find-clear' }));
    }
    if (onApply) onApply(shownNow);
  };
  input.addEventListener('input', apply);
  input.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && input.value) { ev.preventDefault(); ev.stopPropagation(); clear(); } });
  apply();
  return { box, foot, shown: () => shownNow };
}

// A list of events to tick and mark, for pivot results, search results, and the events a count opened. Each row is a
// grid: tick, review-state badge, time, offset, host, and the event, then the `column`, as { head, value(e) }, at the
// right with a heading row, such as which end an address was on. The
// heading row is the list's first row and sticks under its head (see stickUnder). `rerender` redraws the list after a
// tick; `afterMark` refreshes it after marks are written. `label(e)` gives the nodes of the event cell and `highlight(text)`
// those of the host cell, which search uses to mark its terms. `offsets` false leaves out the offset column, as a search,
// which has no event to measure from; left out, it is drawn when a row has a gap. `via` is true for the lists of a pivot's
// trail, a pivot's own and a search run from the trail: an event opened from one continues the trail. The list a count opened
// on the Case overview is not one. `find` gives the list a find box (listFind's options), returned as `find`: with a
// find on, Select all reads "Select the 7 shown" and ticks those rows only, ticks made before stay and count for the mark
// buttons, and the head says how many ticked rows the find hides.
export function markableList(events, checked, rerender, afterMark, { label = null, column = null, hiddenTag = 'hidden',
                                                                      highlight = (t) => [t], offsets = null, via = false,
                                                                      find = null } = {}) {
  const all = events.length > 0 && events.every((e) => checked.has(e.uid));   // not by count: another list may share the ticks
  const note = el('input', { type: 'text', class: 'mark-note', 'aria-label': 'Note for the mark',
                             placeholder: checked.size ? `Note for marking ${plural(checked.size, 'event')} (optional)`
                                                       : 'Note for the mark (optional)' });
  note.value = listNotes.get(checked) || '';
  note.addEventListener('input', () => listNotes.set(checked, note.value));
  const markChecked = async (label) => {
    if (!checked.size) { setStatus('Tick the events to mark first.'); return; }
    if (!await applyMark(label, note.value, [...checked])) return;   // the ticks and the note stay for another try
    checked.clear();
    listNotes.delete(checked);
    await afterMark();
  };
  let shown = null;   // the uids the find shows, or null with no find
  const everyShownTicked = () => shown.size > 0 && [...shown].every((uid) => checked.has(uid));
  const selectLabel = () => {
    if (!shown) return all ? 'Select none' : 'Select all';
    return `${everyShownTicked() ? 'Unselect' : 'Select'} the ${shown.size.toLocaleString()} shown`;
  };
  const selectAll = button('Select all', () => {
    if (shown) {
      const every = everyShownTicked();
      for (const uid of shown) { if (every) checked.delete(uid); else checked.add(uid); }
    } else if (all) checked.clear();
    else for (const e of events) checked.add(e.uid);
    rerender();
  });
  selectAll.textContent = selectLabel();
  const buttons = [
    selectAll,
    button(checked.size ? `Mark ${checked.size} Malicious` : 'Mark Malicious', () => markChecked('Malicious')),
    button(checked.size ? `Mark ${checked.size} Suspicious` : 'Mark Suspicious', () => markChecked('Suspicious')),
    note,
    button(checked.size ? `Tag ${checked.size} as...` : 'Tag as...', (e) => {
      if (!checked.size) { setStatus('Tick the events to tag first.'); return; }
      const r = e.currentTarget.getBoundingClientRect();
      openTagPicker([...checked], r.left, r.bottom + 2);
    })];
  const withOffset = offsets ?? events.some((e) => e.gap_s != null);
  // The heading row has no tick box: "Mark" spans the tick's column and the badge's, so it lines up with both
  const cell = (cls, ...nodes) => el('span', { class: cls }, ...nodes);
  const head = el('li', { class: 'rel-head', 'aria-hidden': 'true' },
    cell('rel-mark', 'Mark'), cell('rel-time', 'Time (UTC)'),
    ...(withOffset ? [cell('off', 'Offset')] : []), cell('rel-host', 'Host'), cell('rel-event', 'Event'),
    ...(column ? [cell('rel-col', column.head)] : []));
  head.querySelector('.rel-mark').title = 'Review state: U unreviewed, A authorized, S suspicious, M malicious';
  if (column) head.querySelector('.rel-col').title = column.title || column.head;
  const rows = events.map((e) => {
    const box = el('input', { type: 'checkbox', 'aria-label': 'Tick to mark' });
    box.checked = checked.has(e.uid);
    box.addEventListener('change', () => { if (box.checked) checked.add(e.uid); else checked.delete(e.uid); rerender(); });
    const suggested = markState(e.mark).suggested;
    const tag = S.viewSpec && !e.shown ? hiddenTag : suggested ? `suggests ${suggested.toLowerCase()}` : '';
    // A click anywhere on the row but its tick box opens the event, since the text alone is 581 px of a
    // 1,324 px row.
    return el('li', { class: 'rel-row', 'data-uid': e.uid, onclick: (ev) => { if (ev.target !== box) { S.trailVia = via; jumpTo(e); } } },
      box, markBadge(e), cell('rel-time', fmtUs(e.ts)),
      ...(withOffset ? [el('span', { class: Math.abs(e.gap_s) >= 60 ? 'off far' : 'off', title: gapTitle(e.gap_s) }, fmtGap(e.gap_s))] : []),
      el('span', { class: 'rel-host', title: e.host }, ...highlight(e.host)),
      el('span', { class: 'rel-event' },
         withTitle(el('span', { class: 'rel-text' }, ...(label ? label(e) : [`${codePrefix(e)}${e.msg}`]))),
         ...(tag ? [el('span', { class: 'tag' }, tag)] : [])),
      ...(column ? [el('span', { class: 'rel-col' }, column.value(e))] : []));   // last, so the column lines up
  });
  const wide = withOffset && events.some((e) => Math.abs(e.gap_s) >= 86400);   // a day or more needs the wider offset cell
  const list = el('ul', { class: `rows${withOffset ? '' : ' no-off'}${wide ? ' wide-off' : ''}${offsets === false ? ' search' : ''}${column ? ' with-col' : ''}` },
                  head, ...rows);
  if (!find) return { buttons, list, find: null };
  // The ticks the mark buttons act on that aren't a shown row of this list: rows the find hides, and ticks another list
  // left in the shared set, as a pivot keeps them across some pivots
  const hiddenTicks = el('span', { class: 'find-ticks', hidden: '' });
  const listed = new Set(events.map((e) => e.uid));
  const found = listFind(list, { ...find, onApply: (set) => {
    shown = set;
    selectAll.textContent = selectLabel();
    const here = set || listed;
    const elsewhere = [...checked].filter((uid) => !here.has(uid)).length;
    hiddenTicks.hidden = !elsewhere;
    hiddenTicks.textContent = elsewhere ? `${plural(elsewhere, 'ticked event')} ${elsewhere === 1 ? "isn't" : "aren't"} shown here` : '';
  } });
  found.box.append(hiddenTicks);
  return { buttons, list, find: found };
}

// The Event page is awaited before the view moves, so a caller that then takes a pivot, as a To investigate count does,
// finds the page on screen.
export async function jumpTo(e, add = false) {
  if (add) S.selected.add(e.uid); else S.selected = new Set([e.uid]);
  if (S.focus !== e.uid) S.windowLinks = [];
  S.focus = e.uid;
  await loadDetails(e.uid, e.ts);
  // An event without a time has no place on the timeline: its Event page opens and the view stays
  if (e.ts == null) { draw(); return; }
  const half = 5 * 60 * 1000, at = e.ts / 1000, span = S.view.end - S.view.start;
  const inView = at > S.view.start + span * 0.05 && at < S.view.end - span * 0.05;
  if (inView && span <= 2 * half) { draw(); return; }   // already in a close view: select without moving
  await animateView(at - half, at + half);
}
