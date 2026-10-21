// Attack-phase and technique tags: ATT&CK tactics in kill-chain order, techniques picked from
// Enterprise ATT&CK's list (attack.js, as a finding's are), and the analyst's own tags, journaled like marks. Hayabusa's
// ATT&CK tags show as suggestions to accept or dismiss. An older technique tag off the list shows flagged, as in a finding.

import { attackPicker } from './attack.js';
import { askSelection, CONFIRM_ABOVE } from './confirm.js';
import { $, api, el, plural, post, reportAction, S, setStatus } from './core.js';
import { fetchView } from './data.js';
import { button, loadDetails } from './event_page.js';
import { reloadLanes } from './lanes.js';
import { closeQuickMenu, menuItem, placeMenu } from './quick_menu.js';
import { renderViewPanel } from './view.js';

export const UNTAGGED = 'Untagged';

// Kill-chain position of a tactic lane, with Untagged last.
export function tacticOrder(name) {
  if (name === UNTAGGED) return 1000;
  const i = (S.meta.tactics || []).findIndex((t) => t.name === name);
  return i < 0 ? 999 : i;
}

export function tagLabel(key) {
  const at = key.indexOf(':');
  const kind = key.slice(0, at), value = key.slice(at + 1);
  if (kind !== 'tactic') return value;
  const t = (S.meta.tactics || []).find((x) => x.id === value);
  return t ? t.name : value;
}

const shown = (text) => (text.includes(':') ? tagLabel(text) : text);

// A hand-picked selection above CONFIRM_ABOVE events asks first, and the tag then carries the count confirmed.
export async function applyTags(uids, { add = [], remove = [], via = '' } = {}) {
  const n = uids.length === 1 ? 'one event' : `${uids.length} events`;
  const consent = {};
  if (uids.length > CONFIRM_ABOVE) {
    const action = add.length ? `Tag ${n}: ${add.map(shown).join(', ')}` : `Untag ${n}: ${remove.map(shown).join(', ')}`;
    if (!await askSelection({ action, uids })) return false;
    consent.confirmed = { count: uids.length };
  }
  let res;
  try { res = await post('/api/tag', { uids, add, remove, ...(via ? { via } : {}), ...consent }); }
  catch (err) { setStatus(`Tag failed: ${err.message}`); return false; }
  await afterTagChange(uids);
  reportAction(add.length ? `Tagged ${n}: ${add.map(shown).join(', ')}` : `Removed from ${n}: ${remove.map(shown).join(', ')}`, res.server_ms);
  return true;
}

export async function decideTagSuggestions(uids, keys, decision) {
  let res;
  try { res = await post('/api/tag_suggestion', { uids, tags: keys, decision }); }
  catch (err) { setStatus(`Change failed: ${err.message}`); return; }
  await afterTagChange(uids);
  reportAction(`${decision === 'dismissed' ? 'Dismissed' : 'Restored'}: ${keys.map(tagLabel).join(', ')}`, res.server_ms);
}

async function afterTagChange(uids) {
  // Tactic lanes and a View on tags depend on tags, so the lanes reload; the counts in the View panel follow.
  if (S.groupby.includes('tactic') || S.filterId) await reloadLanes();
  await fetchView();
  if (S.focus && uids.includes(S.focus)) loadDetails(S.focus);
  if (!$('viewPanel').hidden) {
    try { S.tagCounts = await api('/api/tags'); } catch (_) { /* the panel keeps its old counts */ }
    renderViewPanel();
  }
}

// The tag picker, in the shared popup menu: the 15 tactics, a technique picked from the ATT&CK list, or the analyst's own
// tag. `current` holds the keys the one event being tagged already has, so a click on one of those tactics removes it, and
// the technique list leaves those techniques out.
export async function openTagPicker(uids, x, y, current = new Set()) {
  closeQuickMenu();
  if (!uids.length) { setStatus('Select or tick the events to tag first.'); return; }
  const token = S.menuToken;
  let own = [];
  try { own = (await api('/api/tags')).tags.filter((t) => t.kind === 'tag' && t.count).map((t) => t.label); }
  catch (_) { /* the list of earlier tags is only a convenience */ }
  if (token !== S.menuToken) return;
  const many = uids.length > 1;
  const tactics = S.meta.tactics.map((t) => {
    const key = `tactic:${t.id}`, on = !many && current.has(key);
    return menuItem(on ? `✓ ${t.name}` : t.name, () => applyTags(uids, on ? { remove: [key] } : { add: [key] }),
                    { title: on ? `${t.id}; click to remove` : t.id, cls: on ? 'on' : '' });
  });
  const had = many ? [] : [...current].filter((k) => k.startsWith('technique:')).map((k) => k.slice(10));
  const technique = attackPicker((id) => {
    closeQuickMenu();
    applyTags(uids, { add: [`technique:${id}`] });
  }, had);
  const mine = el('input', { type: 'text', placeholder: 'Your own tag', size: '16', list: 'ownTagList', 'aria-label': 'Your own tag' });
  const add = () => {
    const value = mine.value.trim();
    if (!value) { mine.focus(); return; }
    closeQuickMenu();
    applyTags(uids, { add: [`tag:${value}`] });
  };
  mine.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') add(); });
  const menu = $('quickMenu');
  menu.setAttribute('aria-label', 'Tag events');
  menu.replaceChildren(
    el('div', { class: 'menu-head' }, el('div', {}, many ? `Tag ${uids.length} events` : 'Tag this event'),
       el('div', { class: 'muted' }, 'ATT&CK tactics, in kill-chain order')),
    el('div', { class: 'tactic-grid' }, ...tactics), el('hr'),
    el('div', { class: 'menu-technique' }, el('span', {}, 'Technique'), technique.node),
    el('div', { class: 'menu-foot' }, 'Your own ', mine, ' ', button('Add', add)),
    el('datalist', { id: 'ownTagList' }, ...own.map((o) => el('option', { value: o }))));
  placeMenu(x, y);
  const first = menu.querySelector('button:not([disabled])');
  if (first) first.focus();
}

export const SUGGESTIONS_OPEN_KEY = 'glessner.tagSuggestionsOpen';   // per-browser: whether Hayabusa's suggested tags start open

// The Event page's tag parts, for the header. `plus` is the + Tag button, which sits in the header's second
// row. `toggle` is the "N suggested tags" fold toggle beside it, when Hayabusa suggests tags. `rows` go in the header's
// third row: the event's own tags, and the suggestions, which show only while the toggle is open. On real cases Hayabusa
// suggests tags on most events it hits, so a full row of them would make the common event three rows tall.
export function tagZone(ev, uid, n) {
  if (n > 1) {
    return { plus: button(`Tag ${n} selected events`, (e) => {
      const r = e.currentTarget.getBoundingClientRect();
      openTagPicker([...S.selected], r.left, r.bottom + 2);
    }), toggle: null, rows: [] };
  }
  const tags = ev.tags || [], suggested = ev.tag_suggestions || [];
  // A technique's hover names it; an older one off the ATT&CK list is dashed with the server's flag, and × still removes it
  const chips = tags.map((t) => el('span', { class: `tagchip ${t.kind}${t.flag ? ' off-list' : ''}`,
    title: `${t.kind === 'tactic' ? `${t.key.slice(7)}, ` : ''}${t.name ? `${t.name}, ` : ''}` +
           `tagged by ${t.who}, ${String(t.at).slice(0, 16).replace('T', ' ')} UTC` +
           (t.via === 'hayabusa' ? ', accepted from Hayabusa' : '') },
    t.label, t.flag ? el('span', { class: 'flag' }, ` (${t.flag})`) : '',
    button('×', () => applyTags([uid], { remove: [t.key] }), { 'aria-label': `Remove the tag ${t.label}` })));
  const plus = button('+ Tag', (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    openTagPicker([uid], r.left, r.bottom + 2, new Set(tags.map((t) => t.key)));
  }, { class: 'quiet' });
  const rows = chips.length ? [el('div', { class: 'verdict-row tags' }, el('span', { class: 'muted' }, 'Tags'), ...chips)] : [];
  let toggle = null;
  if (suggested.length) {
    const keys = suggested.map((s) => s.key);
    let open = false;
    try { open = localStorage.getItem(SUGGESTIONS_OPEN_KEY) === '1'; } catch (_) { /* storage blocked */ }
    const box = el('div', { class: 'verdict-row tags small' }, el('span', { class: 'muted' }, 'Hayabusa suggests'),
      // Accept and dismiss at opposite ends, each with its own area and color.
      ...suggested.map((s) => el('span', { class: `tagchip suggested split ${s.kind}` },
        button('✓', () => applyTags([uid], { add: [s.key], via: 'hayabusa' }),
               { class: 'end accept', 'aria-label': `Accept the tag ${s.label}`, title: 'Accept' }),
        // A rule's revoked ID is suggested as its replacement, and the hover says so
        el('span', { class: 'label', title: s.origin ? `Hayabusa's rule tags ${s.origin} (revoked; now ${s.label})` : s.name || '' },
           s.label),
        button('×', () => decideTagSuggestions([uid], [s.key], 'dismissed'),
               { class: 'end dismiss', 'aria-label': `Dismiss the tag ${s.label}`, title: 'Dismiss' }))),
      button('Accept all', () => applyTags([uid], { add: keys, via: 'hayabusa' }), { class: 'quiet' }),
      button('Dismiss all', () => decideTagSuggestions([uid], keys, 'dismissed'), { class: 'quiet' }));
    const arrow = el('span', { 'aria-hidden': 'true' });
    toggle = el('button', { type: 'button', class: 'tw', title: "Hayabusa's ATT&CK tags for this event, to accept or dismiss" },
                plural(suggested.length, 'suggested tag'), ' ', arrow);
    const sync = () => {
      box.hidden = !open;
      arrow.textContent = open ? '▾' : '▸';
      toggle.setAttribute('aria-expanded', String(open));
    };
    toggle.addEventListener('click', () => {
      open = !open;
      sync();
      try { localStorage.setItem(SUGGESTIONS_OPEN_KEY, open ? '1' : '0'); } catch (_) { /* storage blocked */ }
    });
    sync();
    rows.push(box);
  }
  return { plus, toggle, rows };
}
