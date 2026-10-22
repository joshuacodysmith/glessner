// The View flyout: what the timeline shows, by mark and by values pinned from events'
// fields, apart from the Sources flyout's choice of what's available. Hidden events still count for pivots, links,
// and search. Pivot results the view hides are drawn faded until they're marked, so the analyst can build the chain:
// show the marked events, pivot, mark what belongs, repeat.

import { $, api, el, HINTS, panelBand, plural, reportAction, S, setStatus, syncPanelButtons } from './core.js';
import { scheduleFetch } from './data.js';
import { button } from './event_page.js';
import { applyFilter } from './filters.js';
import { resize } from './main.js';
import { closeQuickMenu, menuItem, placeMenu } from './quick_menu.js';
import { addToSearch } from './search.js';
import { renderStateLine } from './state_line.js';
import { tagLabel } from './tags.js';

export const VIEW_MARKS = ['Malicious', 'Suspicious', 'Suggested', 'Authorized', 'Unreviewed'];
const PRESETS = [['Chain', ['Malicious', 'Suspicious'], 'Events marked Malicious or Suspicious: the chain so far'],
                 ['Review', ['Suggested'], 'Events with a pending suggestion'],
                 ['All', null, 'Everything the Sources allow']];
const FADE_KEY = 'glessner.fadePivotResults';   // per-browser preference
const FOLD_KEY = 'glessner.viewFolds';   // per-browser: the panel's sections the analyst folded or unfolded
const VALUE_LABEL = { ip: 'Source IP', port: 'Port', dest_ip: 'Destination IP', dest_port: 'Destination port',
  user: 'Account', host: 'Host', code: 'Event ID', provider: 'Provider',
  channel: 'Channel', computer: 'Computer name', logon_type: 'Logon type', logon_id: 'Logon ID', workstation: 'Workstation',
  process: 'Process', command_line: 'Command line', path: 'File', registry_key: 'Registry key', registry_value: 'Registry value',
  parent: 'Parent process', parent_command_line: 'Parent command line', registry_data: 'Registry data',
  tool: 'Tool', artifact: 'Artifact', run: 'Run', file: 'Evidence file', mark: 'Mark', role: 'Role' };
const valueLabel = (k) => (k === 'search' ? 'Search' : k === 'tag' ? 'Tag' : k === 'tactic' ? 'Tactic lane'
  : k.startsWith('data.') ? k.slice(5) : VALUE_LABEL[k] || k);

export function fadeOn() {
  try { return localStorage.getItem(FADE_KEY) !== 'off'; } catch (_) { return true; }
}

function setFadeOn(on) {
  try { localStorage.setItem(FADE_KEY, on ? 'on' : 'off'); } catch (_) { /* kept for this page only */ }
}

// Which sections of the panel are folded, as the analyst left them: { marks, tags, values } of true (folded) or false. A
// section with no entry takes its own start, so Tactics and tags starts folded while none of its values is on. Kept in the
// page too, so a browser that blocks storage still holds a fold from one redraw of the panel to the next.
const folds = {};
function foldOf(id, start) {
  if (id in folds) return folds[id];
  try {
    const saved = JSON.parse(localStorage.getItem(FOLD_KEY) || '{}');
    if (saved && typeof saved[id] === 'boolean') return saved[id];
  } catch (_) { /* no saved folds */ }
  return start;
}

function setFold(id, folded) {
  folds[id] = folded;
  try {
    const saved = JSON.parse(localStorage.getItem(FOLD_KEY) || '{}');
    localStorage.setItem(FOLD_KEY, JSON.stringify({ ...(saved && typeof saved === 'object' ? saved : {}), [id]: folded }));
  } catch (_) { /* kept for this page only */ }
}

// A section of the panel: its heading is a button that folds it, and a folded one says how many of its values are on.
// `start` is whether it starts folded when the analyst has not chosen.
function section(id, title, on, start, ...body) {
  const folded = foldOf(id, start);
  const box = el('div', { class: 'vsec', id: `vsec-${id}` }, ...body);
  box.hidden = folded;
  const arrow = el('span', { class: 'fold-arrow', 'aria-hidden': 'true' }, folded ? '▸' : '▾');
  const count = el('span', { class: 'fold-count muted' }, on);
  count.hidden = !folded;
  const toggle = el('button', { type: 'button', class: 'fold', 'aria-expanded': String(!folded), 'aria-controls': box.id,
                                title: folded ? `Show the ${title.toLowerCase()} values` : `Fold ${title.toLowerCase()} away` },
                    arrow, el('span', { class: 'fold-title' }, title), count);
  toggle.addEventListener('click', () => {
    const now = !box.hidden;   // hidden after this click
    setFold(id, now);
    box.hidden = now;
    count.hidden = !now;
    arrow.textContent = now ? '▸' : '▾';
    toggle.setAttribute('aria-expanded', String(!now));
    toggle.title = now ? `Show the ${title.toLowerCase()} values` : `Fold ${title.toLowerCase()} away`;
  });
  return [el('h3', {}, toggle), box];
}

export const viewCount = () => (S.viewSpec ? S.viewSpec.marks.length + S.viewSpec.values.length : 0);

// The filter's view part, for /api/filter; nothing when the view is off.
export function viewPart() {
  if (!S.viewSpec) return {};
  return { view: S.viewSuggestedTags ? { ...S.viewSpec, suggested_tags: true } : S.viewSpec, faded: fadeOn() ? S.faded : [] };
}

// Tag values are the ones Include suggested tags widens: a tag, or a tactic other than Untagged, as the server's
// filters.widened decides.
const isTagValue = (p) => 'tag' in p || ('tactic' in p && p.tactic !== 'Untagged');

export function describeValue(p) {
  const text = (k, v) => (k === 'tag' ? (v === '*' ? 'any' : tagLabel(v)) : v.length > 60 ? `${v.slice(0, 57)}...` : v);
  // An address at either end reads as the server's filter description does: "IP 10.0.2.17 at either end".
  return Object.entries(p).map(([k, v], i) => (k === 'addr' ? `IP ${v} at either end`
    : `${i ? valueLabel(k).toLowerCase() : valueLabel(k)} ${text(k, v)}`)).join(', ');
}

// A view that shows nothing is no use, so with no marks and no values left the view goes off and everything shows.
function setSpec(marks, values) {
  S.viewSpec = marks.length || values.length ? { marks: VIEW_MARKS.filter((m) => marks.includes(m)), values } : null;
  if (!S.viewSpec) S.faded = [];
  return applyView();
}

async function applyView() {
  renderViewState();   // the badge and panel answer the click at once; the timeline follows when its data arrives
  renderViewPanel();
  return applyFilter();
}

export function usePreset(marks) {
  return marks ? setSpec(marks, S.viewSpec ? S.viewSpec.values : []) : setSpec([], []);
}

// The View set to exactly these marks and values, as a number on the Case overview opens its events
export function replaceView(marks, values) {
  return setSpec(marks, values);
}

function toggleMark(m, on) {
  const marks = new Set(S.viewSpec ? S.viewSpec.marks : VIEW_MARKS);   // view off: every mark shows
  if (on) marks.add(m); else marks.delete(m);
  const values = S.viewSpec ? S.viewSpec.values : [];
  return marks.size === VIEW_MARKS.length && !values.length ? setSpec([], []) : setSpec([...marks], values);
}

export function addViewValue(pred) {
  const values = S.viewSpec ? [...S.viewSpec.values] : [];
  if (!values.some((p) => samePred(p, pred))) values.push(pred);
  reportAction(`Added to the view filter: ${describeValue(pred)}`);   // the last action, which the redraw keeps
  return setSpec(S.viewSpec ? S.viewSpec.marks : [], values);
}

export function removeViewValue(pred) {
  if (!S.viewSpec) return Promise.resolve();
  reportAction(`Removed from the view filter: ${describeValue(pred)}`);
  return setSpec(S.viewSpec.marks, S.viewSpec.values.filter((p) => !samePred(p, pred)));
}

// Two values are the same filter when their fields match, any letter case, as the server compares them.
const valueKey = (p) => JSON.stringify(Object.keys(p).sort().map((k) => [k, String(p[k]).toLowerCase()]));
const samePred = (a, b) => valueKey(a) === valueKey(b);
export const inViewFilter = (pred) => !!S.viewSpec && S.viewSpec.values.some((p) => samePred(p, pred));

// The add-or-remove button for a value: "Add to view filter" until the value is in the
// filter, then "Remove from view filter", which the Event page shows without hovering. Every copy of the button
// relabels when the filter changes, wherever the change came from. `name` words the value, as in a pivot list.
export function viewToggle(pred, { name = '', className = 'addview' } = {}) {
  const b = el('button', { type: 'button', class: `viewtoggle ${className}`.trim(), 'data-pred': JSON.stringify(pred) });
  if (name) b.dataset.name = name;
  b.addEventListener('click', (ev) => { ev.stopPropagation(); return inViewFilter(pred) ? removeViewValue(pred) : addViewValue(pred); });
  labelToggle(b);
  return b;
}

// An address row's View toggle is a menu: view the address as the row's
// own end, view it at either end, or search for addr:. Older Sysmon records an inbound connection's remote side as its
// destination, so the row's own end can miss the remote side's other events.
export const ADDRESS_FIELDS = { ip: 'source IP', dest_ip: 'destination IP' };

export function addressToggle(pred) {
  const [[field, value]] = Object.entries(pred);
  const either = { addr: value };
  const b = el('button', { type: 'button', class: 'viewtoggle addview', 'aria-haspopup': 'menu', 'aria-expanded': 'false',
                           'data-pred': JSON.stringify(pred), 'data-either': JSON.stringify(either) });
  const check = (label, p) => {
    const on = inViewFilter(p);
    const item = menuItem(label, () => (inViewFilter(p) ? removeViewValue(p) : addViewValue(p)),
                          { title: on ? 'In the view filter now; click to take it out' : `Show events with ${describeValue(p)}` });
    item.setAttribute('role', 'menuitemcheckbox');
    item.setAttribute('aria-checked', String(on));
    return item;
  };
  // A press on the button while its menu is open closes the menu, as a menu button does. The
  // document's mousedown has closed it by the time the click arrives, so the press is noted before that.
  let closing = false;
  b.addEventListener('mousedown', () => { closing = S.menuOpener === b && !$('quickMenu').hidden; });
  b.addEventListener('click', (ev) => {
    ev.stopPropagation();
    const close = closing && ev.detail > 0;   // a click from the keyboard has no press
    closing = false;
    closeQuickMenu();
    if (close) return;
    const search = menuItem('', () => addToSearch('addr', value), { cls: 'menu-indent', title: 'Put this term in the search box' });
    search.replaceChildren('Search ', el('code', {}, `addr:${value}`));
    const menu = $('quickMenu');
    menu.setAttribute('aria-label', `View ${value}`);
    menu.replaceChildren(check(`View as ${ADDRESS_FIELDS[field]}`, pred), check('View at either end', either), search);
    const r = b.getBoundingClientRect();
    placeMenu(r.left, r.bottom + 2);
    S.menuOpener = b;
    b.setAttribute('aria-expanded', 'true');
    menu.querySelector('button').focus();
  });
  labelToggle(b);
  return b;
}

function labelToggle(b) {
  if (b.dataset.either) {   // an address row's menu: active while either of its values is in the filter
    const on = inViewFilter(JSON.parse(b.dataset.pred)) || inViewFilter(JSON.parse(b.dataset.either));
    b.replaceChildren(on ? 'In view filter' : 'Add to view filter', el('span', { 'aria-hidden': 'true' }, ' ▾'));
    b.title = on ? 'In the view filter now; open the menu to take it out or view it another way'
                 : 'Show events with this address in the view filter, as recorded or at either end';
    b.classList.toggle('active', on);
    return;
  }
  const on = inViewFilter(JSON.parse(b.dataset.pred)), name = b.dataset.name ? ` ${b.dataset.name}` : '';
  b.textContent = on ? `Remove${name} from view filter` : `Add${name} to view filter`;
  b.title = on ? 'In the view filter now; click to take it out' : 'Show events with this value in the view filter (any letter case)';
  b.classList.toggle('active', on);
}

// After a host split or its undo: a View value naming a host that's gone matches nothing, so it goes. Returns
// how many went; the caller registers the filter again.
export function dropGoneHosts(known) {
  if (!S.viewSpec) return 0;
  const values = S.viewSpec.values.filter((p) => !('host' in p) || known.has(p.host));
  const n = S.viewSpec.values.length - values.length;
  if (!n) return 0;
  S.viewSpec = values.length || S.viewSpec.marks.length ? { ...S.viewSpec, values } : null;
  if (!S.viewSpec) S.faded = [];
  renderViewState();
  renderViewPanel();
  return n;
}

export function refreshViewToggles() {
  for (const b of document.querySelectorAll('button.viewtoggle')) labelToggle(b);
}

// Pivot results to show faded while the view hides them; a new pivot replaces them.
export function setFaded(uids) {
  S.faded = uids;
  return S.viewSpec && fadeOn() ? applyView() : Promise.resolve();
}

// For the status line: the view in a few words, and how many events show only as faded pivot results.
export function viewNote(data) {
  if (!S.viewSpec) return '';
  const v = S.viewSpec;
  const what = [...v.marks, ...v.values.map(describeValue)].join(', ');
  const suggested = S.viewSuggestedTags && v.values.some(isTagValue) ? ', suggested tags included' : '';
  const faded = data.events ? data.events.filter((e) => e.faded).length : 0;
  return `View: ${what}${suggested}${faded ? `, plus ${faded.toLocaleString()} faded` : ''}`;
}

export function renderViewState() {
  refreshViewToggles();
  const n = viewCount(), badge = $('viewCount');
  badge.hidden = !n;
  badge.textContent = `${n} on`;
  $('viewButton').title = n ? `${HINTS.viewButton} It's on now; the state line says what it hides.` : HINTS.viewButton;
  renderStateLine();
}

export async function toggleViewPanel(open) {
  const panel = $('viewPanel');
  panel.hidden = open === undefined ? !panel.hidden : !open;
  if (!panel.hidden) $('filterPanel').hidden = true;   // one flyout at a time
  syncPanelButtons();
  resize();
  scheduleFetch();
  if (panel.hidden) return;
  try {
    const [marks, tags] = await Promise.all([api('/api/marks'), api('/api/tags')]);
    S.markCounts = marks.counts;
    S.tagCounts = tags;
  } catch (err) { setStatus(err.message); }
  renderViewPanel();
}

export function renderViewPanel() {
  const panel = $('viewPanel');
  if (panel.hidden) return;
  const v = S.viewSpec;
  const counts = S.markCounts || {};
  const presetOn = (marks) => (marks ? !!v && !v.values.length && v.marks.join() === marks.join() : !v);
  const presets = el('div', { class: 'presets' }, ...PRESETS.map(([name, marks, title]) =>
    button(name, () => usePreset(marks), { class: presetOn(marks) ? 'on' : '', title })));
  const markRows = VIEW_MARKS.map((m) => {
    const box = el('input', { type: 'checkbox', 'aria-label': `Show events marked ${m}` });
    box.checked = !v || v.marks.includes(m);
    box.addEventListener('change', () => toggleMark(m, box.checked));
    return el('label', { class: 'vrow' }, box, el('span', { class: 'name' }, m),
              el('span', { class: 'n' }, counts[m] != null ? counts[m].toLocaleString() : ''));
  });
  const pinned = v ? v.values.filter((p) => !('tag' in p)) : [];   // tags show as checkboxes under Tactics
  const values = pinned.length
    ? el('div', { class: 'fchips' }, ...pinned.map((p) => el('span', { class: 'fchip' }, describeValue(p),
        button('×', () => removeViewValue(p), { 'aria-label': `Remove ${describeValue(p)} from the view filter` }))))
    : el('p', { class: 'muted' }, 'None yet. Use Add to view filter beside any field on the Event page, on a pivot list, or on a search.');
  const fade = el('input', { type: 'checkbox' });
  fade.checked = fadeOn();
  fade.addEventListener('change', () => { setFadeOn(fade.checked); applyView(); });
  const fadedNote = v && S.faded.length && fadeOn()
    ? [el('p', { class: 'muted' }, `${plural(S.faded.length, 'pivot result')} shown faded. `,
          button('Clear them', () => setFaded([])))]
    : [];
  const tagsOn = v ? v.values.filter((p) => 'tag' in p).length : 0;
  // Close gives the focus back to the View button, since the panel it was in hides
  const close = () => { toggleViewPanel(false); $('viewButton').focus(); };
  panel.replaceChildren(
    panelBand('View filter', button('Show all', () => usePreset(null)),
              button('Close', close, { class: 'panel-close', title: 'Close the View filter panel', 'aria-label': 'Close the View filter panel' })),
    el('p', { class: 'muted' }, 'What the timeline shows. Hidden events still count for pivots, links, and search.'),
    presets,
    ...section('marks', 'Marks', `${v ? v.marks.length : VIEW_MARKS.length} of ${VIEW_MARKS.length} on`, false, ...markRows),
    ...section('tags', 'Tactics and tags', tagsOn ? `${tagsOn} on` : 'none on', !tagsOn, ...tagRows()),
    ...section('values', 'Values', pinned.length ? `${pinned.length} on` : 'none on', false, values),
    el('label', { class: 'vrow fade' }, fade, el('span', { class: 'name' }, 'Fade in pivot results until marked')),
    ...fadedNote);
}

// One checkbox per tag in use, in kill-chain order, and Any tag. A checked tag is a View value, so tagged events
// show. The suggested count is Hayabusa's pending suggestions, which the View shows only with Include
// suggested tags on, so a tag that only Hayabusa suggests can be checked only then.
function tagRows() {
  const counts = S.tagCounts;
  const used = counts ? counts.tags.filter((t) => t.count || t.suggested) : [];
  if (!used.length) {
    return [el('p', { class: 'muted' }, 'No tags yet. Tag events from the Event page, the right-click menu, or a list.')];
  }
  const row = (pred, label, count, suggested, flag = '') => {
    const box = el('input', { type: 'checkbox', 'aria-label': `Show events tagged ${label}` });
    box.checked = inViewFilter(pred);
    const usable = count || (S.viewSuggestedTags && suggested);
    box.disabled = !usable && !box.checked;   // a checked one stays clickable, so it can be taken out
    box.addEventListener('change', () => (box.checked ? addViewValue(pred) : removeViewValue(pred)));
    // A tag only Hayabusa suggests says how to show it, so its disabled box has a reason.
    const title = !suggested ? ''
      : usable ? `${suggested.toLocaleString()} more suggested by Hayabusa`
        : `${plural(suggested, 'event')} suggested by Hayabusa, none tagged yet. Turn on Include suggested tags to show them.`;
    if (title) box.title = title;
    return el('label', { class: `vrow${usable ? '' : ' none'}`, title },
              // an older technique tag off the ATT&CK list carries the server's flag, as on its chip
              box, el('span', { class: 'name' }, label, flag ? el('span', { class: 'flag' }, ` (${flag})`) : ''),
              el('span', { class: 'n' }, `${count.toLocaleString()}${suggested ? ` · ${suggested.toLocaleString()} suggested` : ''}`));
  };
  const rows = [...used.map((t) => row({ tag: t.key }, t.label, t.count, t.suggested, t.flag)),
                row({ tag: '*' }, 'Any tag', counts.any, counts.any_suggested || 0)];
  return used.some((t) => t.suggested) || S.viewSuggestedTags ? [includeSuggested(), ...rows] : rows;
}

// Include suggested tags. Off, the tag values match the analyst's tags only; on,
// Hayabusa's pending suggestions too, never dismissed ones. It's kept with the View in the page's memory, so it's off
// again after a reload, as the View is.
function includeSuggested() {
  const box = el('input', { type: 'checkbox', 'aria-label': 'Include suggested tags' });
  box.checked = S.viewSuggestedTags;
  box.addEventListener('change', () => {
    S.viewSuggestedTags = box.checked;
    return S.viewSpec && S.viewSpec.values.some(isTagValue) ? applyView() : renderViewPanel();
  });
  return el('label', { class: 'vrow include' }, box,
            el('span', { class: 'name' }, 'Include suggested tags ', el('span', { class: 'muted' }, "(Hayabusa's, not yet accepted)")),
            el('span'));
}
