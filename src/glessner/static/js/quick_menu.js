import { $, api, cut, el, fmtUs, HIT_PX, MARKS, PIVOT_LABELS, plural, S, setStatus } from './core.js';
import { animateView } from './data.js';
import { draw } from './draw.js';
import { applyMark, decide, eventBadge, eventKind, eventUrl, loadDetails } from './event_page.js';
import { openLaneMenu } from './hosts.js';
import { KIND_CUT, select, showPileList } from './interaction.js';
import { pivot } from './pages.js';
import { openTagPicker } from './tags.js';

// ---------- quick-action menu ----------

export const QUICK_HIDDEN_KEY = 'glessner.quickActionsHidden';   // per-browser: the actions this analyst turned off
// The pivots of Find related, in the order Customize lists them. One id covers every row of its pivot, such as each address of
// Same IP at either end. Stored as the hidden set, so a pivot added later shows until the analyst turns it off.
const FIND_RELATED = ['session', 'account', 'source_ip', 'connection', 'file', 'file_name', 'addr', 'window', 'service_name',
                      'workstation', 'flow', 'task_name', 'rule'];
export const QUICK_ACTIONS = [
  ...MARKS.map((m) => ({ id: `mark:${m}`, group: 'Mark', label: `Mark ${m}` })),
  { id: 'suggestion:accept', group: 'Suggestions', label: 'Accept a suggestion' },
  { id: 'suggestion:reject', group: 'Suggestions', label: 'Reject a suggestion' },
  { id: 'suggestion:restore', group: 'Suggestions', label: 'Restore a rejected suggestion' },
  ...FIND_RELATED.map((kind) => ({ id: `pivot:${kind}`, group: 'Find related',
                                  label: kind === 'window' ? 'Same host within ±N s' : PIVOT_LABELS[kind] })),
  { id: 'view:zoom', group: 'View', label: 'Zoom to the event' },
  { id: 'tag', group: 'Tag', label: 'Tag as...' },
];

export function quickHidden() {
  try { return new Set(JSON.parse(localStorage.getItem(QUICK_HIDDEN_KEY) || '[]')); } catch (_) { return new Set(); }
}

export function saveQuickHidden(hidden) {
  try { localStorage.setItem(QUICK_HIDDEN_KEY, JSON.stringify([...hidden])); } catch (_) { /* storage blocked */ }
}

export function closeQuickMenu() {
  const menu = $('quickMenu');
  const focused = menu.contains(document.activeElement);
  menu.hidden = true;
  menu.replaceChildren();
  S.menuToken = (S.menuToken || 0) + 1;   // a menu still loading its event won't open
  // A menu opened from a menu button, such as an address row's View menu, hands focus back to it, as a menu button
  // does, rather than leaving it on the page. Other menus set no opener.
  const opener = S.menuOpener;
  S.menuOpener = null;
  if (opener) {
    opener.setAttribute('aria-expanded', 'false');
    if (focused && opener.isConnected) opener.focus({ preventScroll: true });
  }
}

// Open at the cursor, kept inside the browser window.
export function placeMenu(x, y) {
  const menu = $('quickMenu');
  menu.hidden = false;
  menu.style.left = '0px';
  menu.style.top = '0px';
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.max(4, Math.min(x, window.innerWidth - r.width - 4))}px`;
  menu.style.top = `${Math.max(4, Math.min(y, window.innerHeight - r.height - 4))}px`;
  S.menuAt = { x, y };
}

export function menuItem(label, action, { disabled = false, title = '', cls = '' } = {}) {
  const item = el('button', { type: 'button', role: 'menuitem', class: cls, ...(title ? { title } : {}) }, label);
  if (disabled) item.disabled = true;
  item.addEventListener('click', () => { closeQuickMenu(); action(); });
  return item;
}

export async function pivotFromMenu(uid, kind, seconds, ip = null, more = {}) {
  if (S.focus !== uid) { S.focus = uid; S.windowLinks = []; draw(); }
  await loadDetails(uid);
  await pivot(uid, kind, seconds, ip, more);
}

// One pivot the Event page offers (a ranked row or a plain link of ev.pivots), as the page words and runs it: a window with
// its size, an address with the end it takes, an account with no domain as name only, and the name a file-name row fixes.
function relatedItem(uid, p) {
  const ip = p.pivot === 'addr' ? p.ip || p.value : null;
  const text = p.pivot === 'addr' ? `${p.label}: ${ip}`
    : p.pivot === 'window' ? p.label.replace(/ ±N s$/, ` ±${p.seconds} s`)
      : p.name_only ? `${p.label} (name only, any domain)` : p.label;
  const title = p.warn || (p.pivot === 'connection' ? `Within ±${p.seconds} s of this event, since a source port is reused` : '');
  return menuItem(text, () => pivotFromMenu(uid, p.pivot, p.seconds, ip, { label: p.label, ...(p.name ? { name: p.name } : {}) }),
                  title ? { title } : {});
}

// Find related: the pivots the Event page offers for this event, in its kind's ranked order and then the ones it doesn't
// rank, without counts; then the pivots the event can't take, disabled, with the page's reason. The page's
// search rows are searches, not pivots, and stay on the page.
function relatedItems(ev, uid, show) {
  const g = ev.pivots;
  if (!g || g.error) {
    return [menuItem('Find related', () => {}, { disabled: true, title: `Not available for this event: ${g ? g.error : 'no guidance'}` })];
  }
  const taken = [...g.rows, ...g.plain].filter((p) => p.pivot !== 'search' && show(`pivot:${p.pivot}`));
  const refused = g.not_offered.filter((n) => n.pivot !== 'search' && show(`pivot:${n.pivot}`));
  return [...taken.map((p) => relatedItem(uid, p)),
          ...refused.map((n) => menuItem(n.label || PIVOT_LABELS[n.pivot], () => {}, { disabled: true, title: n.reason }))];
}

export async function openQuickMenu(uid, x, y, pile) {
  closeQuickMenu();
  const token = S.menuToken;
  // A right-click outside the selection selects that event, as in a file list. Inside it, the selection stays.
  if (!S.selected.has(uid)) select(uid, false);
  let ev;
  try { ev = (await api(eventUrl(uid))).event; }
  catch (err) { setStatus(`Could not load the event: ${err.message}`); return; }
  if (token !== S.menuToken) return;
  $('quickMenu').setAttribute('aria-label', 'Quick actions');
  const hidden = quickHidden();
  const show = (id) => !hidden.has(id);
  const n = S.selected.size;
  const sections = [];
  // The Mark items spell the state out, so they carry no badge: the badge stands for the word and never sits beside it
  const marks = MARKS.filter((m) => show(`mark:${m}`)).map((m) => menuItem(n > 1 ? `Mark ${m} (${n} events)` : `Mark ${m}`,
    () => applyMark(m, ''), { cls: `mark-${m.toLowerCase()}`, disabled: n === 1 && ev.mark.label === m,
                              title: n === 1 && ev.mark.label === m ? 'Already marked this way' : '' }));
  if (marks.length) sections.push(marks);
  const decisions = [];
  for (const s of ev.suggestions) {
    if (s.rejected) {
      if (show('suggestion:restore')) decisions.push(menuItem(`Restore the ${s.source} suggestion`, () => decide('restore', s.source, [uid])));
      continue;
    }
    if (show('suggestion:accept')) decisions.push(menuItem(`Accept as ${s.value} (${s.source})`, () => decide('accept', s.source, [uid])));
    if (show('suggestion:reject')) decisions.push(menuItem(`Reject the ${s.source} suggestion`, () => decide('reject', s.source, [uid])));
  }
  if (decisions.length) sections.push(decisions);
  const pivots = relatedItems(ev, uid, show);
  if (pivots.length) sections.push(pivots);
  if (show('view:zoom') && ev.adjusted_ts_us != null) {
    // Zoom to the case's time window around the event; if the timeline is already closer, only center it.
    const half = S.meta.time_window_seconds * 1000, at = ev.adjusted_ts_us / 1000, span = S.view.end - S.view.start;
    sections.push([span > 2 * half
      ? menuItem(`Zoom to ±${S.meta.time_window_seconds} s around it`, () => animateView(at - half, at + half))
      : menuItem('Center the timeline on it', () => animateView(at - span / 2, at + span / 2))]);
  }
  if (show('tag')) {
    const current = n === 1 ? new Set((ev.tags || []).map((t) => t.key)) : new Set();
    sections.push([menuItem(n > 1 ? `Tag ${n} events as...` : 'Tag as...', () => openTagPicker([...S.selected], x, y, current))]);
  }
  sections.push([menuItem('Customize this menu…', () => showQuickCustomize())]);

  const menu = $('quickMenu');
  menu.replaceChildren(menuHead(ev, n, pile), ...sections.flatMap((items, i) => (i ? [el('hr')] : []).concat(items)));
  placeMenu(x, y);
  // Nothing is selected on open: focus is on the menu itself, so a stray Enter or Space right after the right-click
  // marks nothing. The first arrow down takes the first enabled item and the arrow up the last; Tab reaches the head's link.
  menu.focus({ preventScroll: true });
}

// The menu's head: which event the menu is for, its badge, kind, host, and time, its message, and, when other events
// are drawn within the hit radius, how many and a link that lists them all. The Mark items act on every selected event, so
// with a selection of several the head says so, and names the clicked event as one it includes.
function menuHead(ev, n, pile) {
  const when = ev.adjusted_ts_us == null ? 'No time' : `${fmtUs(ev.adjusted_ts_us)} UTC`;
  const others = pile && pile.length > 1 ? pile.length - 1 : 0;
  const more = others
    ? [` · ${plural(others, 'other event')} within ${HIT_PX} px: `,
       menuItem(`show all ${pile.length} here`, () => showPileList(pile),
                { cls: 'linklike', title: `Events drawn within ${HIT_PX} pixels of the pointer` })]
    : [];
  return el('div', { class: 'menu-head' },
    el('div', { class: 'for' }, n > 1 ? `Menu for ${n} selected events` : 'Menu for this event'),
    el('div', { class: 'what' }, ...(n > 1 ? [el('span', { class: 'muted' }, 'including')] : []), eventBadge(ev),
       el('b', {}, `${cut(eventKind(ev), KIND_CUT)} · ${ev.host} · ${when}`)),
    el('div', { class: 'muted' }, ev.message.length > 90 ? `${ev.message.slice(0, 90)}…` : ev.message, ...more));
}

// The checklist of actions the menu shows, saved in this browser.
export function showQuickCustomize() {
  const hidden = quickHidden();
  const menu = $('quickMenu');
  const rows = [];
  let group = '';
  for (const a of QUICK_ACTIONS) {
    if (a.group !== group) { group = a.group; rows.push(el('div', { class: 'menu-group' }, group)); }
    const box = el('input', { type: 'checkbox' });
    box.checked = !hidden.has(a.id);
    box.addEventListener('change', () => { box.checked ? hidden.delete(a.id) : hidden.add(a.id); saveQuickHidden(hidden); });
    rows.push(el('label', {}, box, ` ${a.label}`));
  }
  menu.replaceChildren(
    el('div', { class: 'menu-head' }, el('div', {}, 'Quick-action menu'),
       el('div', { class: 'muted' }, 'Choose the actions it shows. Saved in this browser.')),
    ...rows, el('hr'),
    el('div', { class: 'menu-foot' }, el('button', { type: 'button', onclick: closeQuickMenu }, 'Done')));
  const at = S.menuAt || { x: 100, y: 100 };
  placeMenu(at.x, at.y);
  const first = menu.querySelector('input');
  if (first) first.focus();
}

export function setupQuickMenu() {
  const menu = $('quickMenu');
  $('labels').addEventListener('contextmenu', (ev) => {
    const div = ev.target.closest('.row');
    const row = div && S.rows[Number(div.dataset.row)];
    if (!row || !row.key) return;   // the outside-source lanes keep the browser's menu
    ev.preventDefault();
    openLaneMenu(row, ev.clientX, ev.clientY);
  });
  document.addEventListener('mousedown', (ev) => { if (!menu.hidden && !menu.contains(ev.target)) closeQuickMenu(); });
  window.addEventListener('blur', () => { if (!menu.hidden) closeQuickMenu(); });
  window.addEventListener('resize', () => { if (!menu.hidden) closeQuickMenu(); });
  $('lanes').addEventListener('wheel', () => { if (!menu.hidden) closeQuickMenu(); });
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && !menu.hidden) closeQuickMenu(); });
  menu.addEventListener('keydown', (ev) => {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(ev.key)) return;
    const items = [...menu.querySelectorAll('button:not([disabled]), input')];
    if (!items.length) return;
    const at = items.indexOf(document.activeElement);
    const down = ev.key === 'ArrowDown';
    const next = ev.key === 'Home' ? 0 : ev.key === 'End' ? items.length - 1
      : at < 0 ? (down ? 0 : items.length - 1) : (at + (down ? 1 : -1) + items.length) % items.length;
    items[next].focus();
    ev.preventDefault();
  });
}
