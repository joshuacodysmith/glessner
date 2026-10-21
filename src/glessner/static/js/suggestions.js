import { askGroupDecision } from './confirm.js';
import { api, codePrefix, el, fmtUs, markBadge, S, setStatus } from './core.js';
import { draw } from './draw.js';
import { button, claimDetails, decide, setPage, showingPage } from './event_page.js';
import { jumpTo, listFind } from './pages.js';

// ---------- Suggestions page: one source's pending suggestions, grouped ----------

// 'rule' groups Hayabusa hits by rule title, and Suricata alerts and imported fast alerts by signature.
export const GROUP_BY = [['rule', 'Rule or signature'], ['account', 'Account'], ['host', 'Host'], ['code', 'Event ID']];

// The page last drawn, as showSuggestions takes it, so a reload can draw it again
let shown = null;
export const shownSuggestions = () => shown;

// `limit` lists more than the first 200 of each group, for the confirm's "Show all N first".
export async function showSuggestions(source, groupBy = '', limit = 0) {
  const latest = claimDetails();   // a page asked for after it keeps the panel
  let res;
  try { res = await api(`/api/pending?source=${encodeURIComponent(source)}${groupBy ? `&group_by=${groupBy}` : ''}${limit ? `&limit=${limit}` : ''}`); }
  catch (err) { setStatus(err.message); return; }
  if (!latest()) return;
  groupBy = res.group_by;
  shown = { source, groupBy, limit };
  const loadedAt = new Date();   // what the confirm names as when the page counted
  const value = res.groups.length ? res.groups[0].events[0].value : '';
  const refresh = () => showSuggestions(source, groupBy, limit);
  const act = async (decision, opts) => {
    await decide(decision, source, opts.uids || null, { ...opts, fromEvent: false });
    if (showingPage(`suggestions:${source}`)) refresh();   // not over a page asked for while the decision was made
  };
  // Accept all, Reject all, and a group's Accept N or Reject N ask first: the question names the exact events the
  // page counted when it loaded, and the decision then covers those, not whatever is pending at the click
  const askThen = async (decision, { uids, listed, first, group = null, showAll, host }) => {
    const chosen = await askGroupDecision({ decision, source, value, group, groupBy, uids, listed, first, loadedAt, showAll, host });
    if (chosen) await act(decision, { uids: chosen, confirmed: { count: chosen.length } });
  };
  // The listed events stand out on the timeline, as related events do after a pivot.
  S.related = new Set(res.groups.flatMap((g) => g.events.map((e) => e.uid)));
  S.windowLinks = [];
  draw();
  const groupSelect = el('select', { onchange: () => showSuggestions(source, groupSelect.value) },
    ...GROUP_BY.map(([k, label]) => { const o = el('option', { value: k }, label); if (k === groupBy) o.selected = true; return o; }));
  const expandAll = res.total <= 50;
  const listed = res.groups.reduce((n, g) => n + g.events.length, 0);
  const everyUid = res.groups.flatMap((g) => g.uids || []);
  const firstOfAll = res.groups.flatMap((g) => g.events).sort((a, b) => (a.ts ?? Infinity) - (b.ts ?? Infinity)).slice(0, 3);
  const groups = res.groups.map((g, i) => {
    const body = el('ul', { class: 'sg-events' }, ...g.events.map((e) => el('li', { onclick: () => jumpTo(e) },
      markBadge({ mark: `Suggested: ${e.value}`, suggest_source: source }),   // every event here is unreviewed, with this guess
      el('span', { class: 'sg-text' }, `${fmtUs(e.ts)}  ${e.host}  ${codePrefix(e)}${e.msg}`),
      button('Accept', (ev) => { ev.stopPropagation(); act('accept', { uids: [e.uid] }); }),   // one event acts at once
      button('Reject', (ev) => { ev.stopPropagation(); act('reject', { uids: [e.uid] }); }))));
    if (g.count > g.events.length) {
      body.append(el('li', { class: 'muted sg-more' }, `Showing the first ${g.events.length} of ${g.count.toLocaleString()}. ` +
                                                       'The group buttons cover all of them, and ask first.'));
    }
    // The find box, by group; a group cut at the limit says how far it reaches. Its line sits over the list, inside
    // the fold with it.
    const find = listFind(body, { page: `suggestions:${source}`, name: `group:${groupBy}:${g.key}`, rows: 'li:not(.sg-more)',
                                  cells: '.sg-text', highlight: '.sg-text', covers: "The group's count and buttons still cover",
                                  listed: g.count > g.events.length ? g.events.length : null, total: g.count, more: 'events' });
    const fold = el('div', { class: 'sg-body' }, find.foot, body);
    const open = expandAll || i === 0;
    fold.hidden = !open;
    const twisty = button(open ? '▾' : '▸', () => { fold.hidden = !fold.hidden; twisty.textContent = fold.hidden ? '▸' : '▾'; },
                          { class: 'twisty', 'aria-label': `Show or hide ${g.key}` });
    const n = g.count.toLocaleString();
    const box = el('div', { class: 'sg-group' });
    // Show all first lists the whole group, up to the server's cap, and opens it
    const showAll = g.count > g.events.length ? () => showSuggestions(source, groupBy, g.count) : null;
    const ask = (decision) => askThen(decision, { uids: g.uids || g.events.map((e) => e.uid), listed: g.events.length,
                                                  first: g.events.slice(0, 3), group: g.key, showAll, host: box });
    box.append(
      el('div', { class: 'sg-head' }, twisty, el('strong', {}, g.key),
         // A Suricata group reads "severity 1" and a fast alert group "priority 1", in the alert's own words, colored as
         // the level it ranks with.
         ...(g.level ? [el('span', { class: `chip level-${g.level}` }, g.level_label || g.level)] : []),
         el('span', { class: 'muted' }, `${n} pending`),
         button(`Accept ${n}`, () => ask('accept'), { class: `mark-${value}` }),
         button(`Reject ${n}`, () => ask('reject')), find.box),
      fold);
    return box;
  });
  const slot = el('div', { class: 'confirm-slot' });   // where the page-wide question goes, under the buttons
  const top = el('div', { class: 'actions' },
    button('Accept all', () => askThen('accept', { uids: everyUid, listed, first: firstOfAll, host: slot,
                                                   showAll: listed < res.total ? () => showSuggestions(source, groupBy, res.total) : null }),
           { class: `mark-${value}` }),
    button('Reject all', () => askThen('reject', { uids: everyUid, listed, first: firstOfAll, host: slot,
                                                   showAll: listed < res.total ? () => showSuggestions(source, groupBy, res.total) : null })),
    el('span', { class: 'muted' }, 'Group by'), groupSelect);
  setPage('suggestions', [
    el('h2', {}, `${source} suggests ${value || 'a mark'}: ${res.total.toLocaleString()} pending`),
    top, slot,
    el('p', { class: 'muted' }, `Accept marks the events ${value}. Reject leaves them unreviewed and stops ${source} suggesting them; ` +
       'the Event page can restore a rejected suggestion. Accept all, Reject all, and a group\'s buttons ask first. Click an event to open it.'),
    ...(groups.length ? groups : [el('p', {}, 'Nothing is pending from this source.')]),
  ], { key: `suggestions:${source}`, title: `${source} suggestions`, reopen: refresh });   // regrouping is the same page
}
