import { $, api, el, HINTS, panelBand, plural, post, S, setStatus, syncPanelButtons } from './core.js';
import { fetchView, scheduleFetch } from './data.js';
import { button } from './event_page.js';
import { renderExportScope } from './exports.js';
import { openLaneMenu } from './hosts.js';
import { reloadLanes } from './lanes.js';
import { resize } from './main.js';
import { closeQuickMenu, menuItem, placeMenu } from './quick_menu.js';
import { renderStateLine } from './state_line.js';
import { viewPart } from './view.js';

// ---------- filters: what the timeline shows ----------
// A filter is { only, hide, show } lists of preds; a pred names field values that must all match. The most
// specific rule wins, so a hidden host can still show one of its files: "show" rules are those exceptions.
// Checkboxes come from the server's counts of what the filter shows, so they tell the truth whichever rule
// did the hiding. Filters never change the case and are not kept across a reload.

// A tool's name, as the registry gives it in /api/meta, or its ID.
const toolName = (id) => (S.meta?.tool_names || {})[id] || id;
export const predKey = (p) => JSON.stringify(Object.keys(p).sort().map((k) => [k, p[k]]));
export const covers = (outer, inner) => Object.entries(outer).every(([k, v]) => inner[k] === v);   // outer is as broad or broader
export const filterParam = () => (S.filterId ? `&filter=${S.filterId}` : '');
export const filterCount = () => S.filter.only.length + S.filter.hide.length + S.filter.show.length;
// A file's key in the shown counts. One file can be read by two tools, such as a hive's registry and shellbags
// events, and the panel lists it under each evidence type, so the key names the tool and type as well; a key of host
// and file alone gave both rows the file's whole count.
const fileKey = (host, tool, artifact, file) => [host, tool, artifact, file].join('\t');

// The most specific hide or show rule covering a pred: the one that decides it, if any.
export function rulingRule(p) {
  let best = null;
  for (const kind of ['hide', 'show']) {
    for (const r of S.filter[kind]) {
      if (covers(r, p) && (!best || Object.keys(r).length > Object.keys(best.r).length)) best = { kind, r };
    }
  }
  return best;
}

export function describePred(p) {
  const file = p.file && p.file.split('/').pop();
  const kind = (p.channel && file ? `${p.channel} in ${file}` : p.channel) || file ||
    (p.artifact && p.tool ? `${p.artifact} (${toolName(p.tool)})` : p.artifact || (p.tool && toolName(p.tool))) ||
    (p.run && `run ${p.run}`);
  const scope = [p.host, p.role, p.mark, p.user, p.ip && `source IP ${p.ip}`, p.port && `port ${p.port}`].filter(Boolean);
  if (!kind) return scope.join(', ');
  return scope.length ? `${kind} on ${scope.join(', ')}` : kind;
}

// Counts the changes applyFilter has been asked to apply, so an earlier change's answer can tell it is out of date
let filterChanges = 0;

// Resolves to { id, applied }: the id the change registered, null when it needed none or its registration failed, and
// whether the change is still the filter in force once the timeline has drawn it. applied is false once a later change
// was made while this one registered or drew. A caller that lists events under this change's filter takes its id.
export async function applyFilter() {
  // One registered filter carries both flyouts: the Sources choice and the View. A registration that answers after a
  // later change is dropped: it would put back the filter that change replaced.
  const change = ++filterChanges;
  let id = null;
  try { if (filterCount() || S.viewSpec) id = (await post('/api/filter', { ...S.filter, ...viewPart() })).id; }
  catch (err) {
    if (change === filterChanges) setStatus(`Filter failed: ${err.message}`);   // not over a later change's filter
    return { id: null, applied: false };
  }
  if (change !== filterChanges) return { id, applied: false };
  S.filterId = id;
  // The state line's counts are the last filter's until the lanes answer for this one, so it says "..." meanwhile
  S.lanesShown = null;
  S.sourcesShown = null;
  S.viewShown = null;
  renderFilterState();
  renderExportScope();   // the Findings page's window card and report tick, when it shows
  await Promise.all([refreshShown(), reloadLanes().then(fetchView)]);
  return { id, applied: change === filterChanges };
}

// Show or hide everything a pred covers. Rules inside it go; then one rule is added only where the broader
// rules would decide otherwise, so showing a file inside a hidden host adds a "show" exception.
export function setShown(p, show) {
  const f = S.filter;
  f.hide = f.hide.filter((r) => !covers(p, r));
  f.show = f.show.filter((r) => !covers(p, r));
  const ruling = rulingRule(p);
  const hiddenNow = !!ruling && ruling.kind === 'hide';
  if (show && hiddenNow) f.show.push(p);
  if (!show && !hiddenNow) f.hide.push(p);
  // Showing something that "Show only" leaves out adds it to the shown set.
  if (show && f.only.length && !f.only.some((o) => covers(o, p))) f.only.push(p);
  return applyFilter();
}

export function removeRule(kind, r) {
  S.filter[kind] = S.filter[kind].filter((x) => x !== r);
  if (kind === 'hide') {   // exceptions to a removed hide would do nothing, so they go with it
    S.filter.show = S.filter.show.filter((s) => S.filter.hide.some((h) => covers(h, s) && predKey(h) !== predKey(s)));
  }
  return applyFilter();
}

export function showOnly(p) { S.filter.only = [p]; return applyFilter(); }
export function clearFilters() { S.filter = { only: [], hide: [], show: [] }; return applyFilter(); }

export function renderFilterState() {
  const n = filterCount(), badge = $('filterCount');
  badge.hidden = !n;
  badge.textContent = `${n} on`;
  $('filtersButton').title = n ? `${HINTS.filtersButton} Some are hidden now; the state line says how many events.` : HINTS.filtersButton;
  renderFilterPanel();
  renderStateLine();
}

// What the current filter shows per source file, and per channel within it, from the server; without a filter
// everything shows. An answer for a filter that has changed since it was asked is dropped: the panel's boxes come from
// these counts, so it would show the earlier filter's choices, and a click on a box would act on them.
export async function refreshShown() {
  if ($('filterPanel').hidden || !S.filterId) { S.shown = null; renderFilterPanel(); return; }
  const asked = S.filterId;
  try {
    const res = await api(`/api/shown?filter=${asked}`);
    if (asked !== S.filterId) return;
    S.shown = new Map();
    for (const [host, tool, artifact, file, channel, n] of res.counts) {
      const key = fileKey(host, tool, artifact, file);
      S.shown.set(key, (S.shown.get(key) || 0) + n);
      if (channel) S.shown.set(`${key}\t${channel}`, n);
    }
  } catch (err) { setStatus(err.message); return; }
  renderFilterPanel();
}

// Whether showing a pred can change anything: a rule inside it or over it hides some of it, or "Show only"
// leaves it out. When its hidden part comes only from rules across it, such as a hidden host under a type
// row, showing cannot override those, so a click hides it instead.
export function canShow(p) {
  const ruling = rulingRule(p);
  return S.filter.hide.some((r) => covers(p, r)) || (ruling && ruling.kind === 'hide') ||
         (S.filter.only.length > 0 && !S.filter.only.some((o) => covers(o, p)));
}

// A checkbox for a pred, from how many of its events show: checked when all, part-checked when some.
// A click shows everything it covers when it can, and otherwise hides it.
export function filterBox(p, shown, total) {
  const all = shown >= total;
  const box = el('input', { type: 'checkbox', 'aria-label': `Show ${describePred(p)}` });
  box.checked = shown > 0;
  box.indeterminate = shown > 0 && !all;
  box.addEventListener('change', () => { S.filterApplying = setShown(p, !all && canShow(p)); });   // menus wait on this
  return box;
}

export function countText(shown, total) {
  return shown < total ? `${shown.toLocaleString()} of ${total.toLocaleString()}` : total.toLocaleString();
}

// Hover text for a row not fully shown: how much shows, and the rule that hides it, when one does.
export function rowTitle(p, shown, total, base = '') {
  if (shown >= total) return base;
  const rule = rulingRule(p);
  const why = rule && rule.kind === 'hide' ? ` Hidden by: ${describePred(rule.r)}.` : ' Other filters hide the rest.';
  return `${base ? `${base}. ` : ''}${shown.toLocaleString()} of ${plural(total, 'event')} shown.${shown ? '' : why}`;
}

export async function toggleFilterPanel(open) {
  const panel = $('filterPanel');
  panel.hidden = open === undefined ? !panel.hidden : !open;
  if (!panel.hidden) $('viewPanel').hidden = true;   // one flyout at a time
  syncPanelButtons();
  resize();          // the Timeline panel just changed width; refit the lane labels and canvas now
  scheduleFetch();
  if (panel.hidden) return;
  if (!panel.firstChild) buildFilterPanel();
  if (!S.sources) {
    $('fpTree').replaceChildren(el('p', { class: 'muted' }, 'Counting events by source…'));
    try { S.sources = await api('/api/sources'); } catch (err) { setStatus(err.message); return; }
  }
  await refreshShown();
}

// The panel's fixed parts; renderFilterPanel fills the lists, so the search box keeps focus while typing.
export function buildFilterPanel() {
  const find = el('input', { type: 'search', id: 'fpFind', placeholder: 'Find a file' });
  find.addEventListener('input', () => { S.fpQuery = find.value.trim().toLowerCase(); renderFilterPanel(); });
  $('filterPanel').replaceChildren(
    panelBand('Sources', button('Clear all', clearFilters)),
    el('p', { class: 'muted' }, 'A check means shown on the timeline; counts read "shown of all" when part is hidden. ' +
       'A more specific choice overrides a broader one: hide a host and still show one of its files. Right-click an item for more.'),
    el('div', { id: 'fpChips', class: 'fchips' }),
    el('h3', {}, 'Evidence types, across all hosts'), el('div', { id: 'fpTypes' }),
    el('h3', {}, 'Hosts and files'), find, el('div', { id: 'fpTree' }));
  $('filterPanel').addEventListener('contextmenu', (ev) => {
    const row = ev.target.closest('[data-pred]');
    if (!row) return;
    ev.preventDefault();
    const p = JSON.parse(row.dataset.pred);
    if (p.host && Object.keys(p).length === 1) { openLaneMenu({ key: 'host', label: p.host }, ev.clientX, ev.clientY); return; }
    openItemMenu(p, ev.clientX, ev.clientY, { title: describePred(p) });
  });
}

export function filterRow(p, depth, label, shown, total, { node = '', title = '', info = false } = {}) {
  const open = node && (S.fpOpen.has(node) || !!S.fpQuery);
  const tw = node ? button(open ? '▾' : '▸', () => { S.fpOpen.has(node) ? S.fpOpen.delete(node) : S.fpOpen.add(node); renderFilterPanel(); },
                           { class: 'tw', 'aria-label': `Show or hide what is in ${label}` }) : el('span');
  const hidden = p && shown < total;
  return el('div', { class: `frow d${depth}${info ? ' info' : ''}${hidden && !shown ? ' off' : ''}`,
                     ...(p ? { 'data-pred': JSON.stringify(p) } : {}), ...(node ? { 'data-node': node } : {}),
                     title: p ? rowTitle(p, shown, total, title) : title },
            tw, p ? filterBox(p, shown, total) : el('span'), el('span', { class: 'name' }, label),
            el('span', { class: 'n' }, total == null ? '' : countText(shown, total)));
}

export function renderFilterPanel() {
  const panel = $('filterPanel');
  if (panel.hidden || !S.sources || !panel.firstChild) return;
  const chips = [...S.filter.only.map((p) => [`Only ${describePred(p)}`, () => { S.filter.only = S.filter.only.filter((o) => o !== p); applyFilter(); }]),
                 ...S.filter.hide.map((p) => [`Hiding ${describePred(p)}`, () => removeRule('hide', p)]),
                 ...S.filter.show.map((p) => [`Showing ${describePred(p)}`, () => removeRule('show', p)])];
  $('fpChips').replaceChildren(...(chips.length ? chips.map(([text, remove]) => el('span', { class: 'fchip' }, text,
    button('×', remove, { 'aria-label': `Remove the filter: ${text}` }))) : [el('span', { class: 'muted' }, 'Nothing is hidden.')]));
  // Shown counts per file, summed up to types and hosts. Without a filter, everything shows.
  const shownOf = (h, a, f, channel) => {
    if (!S.shown) return channel ? channel.count : f.count;
    const key = fileKey(h, a.tool, a.artifact, f.file);
    return S.shown.get(channel ? `${key}\t${channel.channel}` : key) || 0;
  };
  const typeShown = new Map();
  const hostShown = new Map(), artShown = new Map();
  for (const h of S.sources.hosts) {
    let hs = 0;
    for (const a of h.artifacts) {
      const as = a.files.reduce((n, f) => n + shownOf(h.host, a, f), 0);
      artShown.set(`${h.host}:${a.tool}:${a.artifact}`, as);
      typeShown.set(`${a.tool}:${a.artifact}`, (typeShown.get(`${a.tool}:${a.artifact}`) || 0) + as);
      hs += as;
    }
    hostShown.set(h.host, hs);
  }
  const types = [];
  for (const t of S.sources.types) {
    const node = `t:${t.tool}:${t.artifact}`;
    types.push(filterRow({ tool: t.tool, artifact: t.artifact }, 0, `${t.artifact} (${toolName(t.tool)} ${t.versions.join(', ')})`,
                         typeShown.get(`${t.tool}:${t.artifact}`) ?? t.count, t.count, { node }));
    if (S.fpOpen.has(node)) for (const r of t.runs) types.push(filterRow(null, 1, `run ${r.run}, ${r.host}`, r.count, r.count, { info: true, title: r.run }));
  }
  const hb = S.sources.hayabusa;
  if (hb.count) types.push(filterRow(null, 0, `Hayabusa ${hb.version}: hits on event log events`, hb.count, hb.count, { info: true }));
  $('fpTypes').replaceChildren(...types);
  const q = S.fpQuery, tree = [];
  for (const h of S.sources.hosts) {
    const match = (f) => !q || f.file.toLowerCase().includes(q);
    const arts = h.artifacts.map((a) => ({ ...a, shownFiles: a.files.filter(match) })).filter((a) => a.shownFiles.length);
    if (!arts.length) continue;
    const hn = `h:${h.host}`;
    tree.push(filterRow({ host: h.host }, 0, h.host, hostShown.get(h.host), h.count, { node: hn }));
    if (!(S.fpOpen.has(hn) || q)) continue;
    for (const a of arts) {
      const an = `a:${h.host}:${a.artifact}`;
      const ap = { host: h.host, tool: a.tool, artifact: a.artifact };
      tree.push(filterRow(ap, 1, `${a.artifact}, ${plural(a.files.length, 'file')}`,
                          artShown.get(`${h.host}:${a.tool}:${a.artifact}`), a.count, { node: an }));
      if (!(S.fpOpen.has(an) || q)) continue;
      const all = S.fpAll.has(an) || q;
      for (const f of (all ? a.shownFiles : a.shownFiles.slice(0, 50))) {
        // A file of several channels, such as a capture's Suricata record types, opens to them
        const fn = f.channels ? `f:${h.host}:${f.file}` : '';
        const fp = { ...ap, file: f.file };
        tree.push(filterRow(fp, 2, f.file.split('/').pop(), shownOf(h.host, a, f), f.count, { title: f.file, node: fn }));
        if (!fn || !(S.fpOpen.has(fn) || q)) continue;
        for (const c of f.channels) tree.push(filterRow({ ...fp, channel: c.channel }, 3, c.channel, shownOf(h.host, a, f, c), c.count));
      }
      if (!all && a.shownFiles.length > 50) {
        tree.push(el('div', { class: 'frow d2 info' }, el('span'), el('span'),
                     button(`${a.shownFiles.length - 50} more`, () => { S.fpAll.add(an); renderFilterPanel(); }, { class: 'linklike' }), el('span')));
      }
    }
  }
  $('fpTree').replaceChildren(...(tree.length ? tree : [el('p', { class: 'muted' }, 'No file matches.')]));
}

// Open the Sources panel at a host's event logs, from "All N channels" in a menu.
export async function openFilterPanelAt(p) {
  S.fpQuery = '';
  const find = $('fpFind');
  if (find) find.value = '';
  if (p.host) { S.fpOpen.add(`h:${p.host}`); S.fpOpen.add(`a:${p.host}:evtx`); S.fpAll.add(`a:${p.host}:evtx`); }
  await toggleFilterPanel(true);
  const row = [...$('fpTree').querySelectorAll('[data-node]')].find((r) => r.dataset.node === `a:${p.host}:evtx`);
  if (row) row.scrollIntoView({ block: 'start' });
}

// The context menu for a lane label or a Sources panel item: Show only, Hide, and what is inside the item.
// Its checkboxes use the same shown counts as the panel and refresh in place, so several can change in a row.
export async function openItemMenu(pred, x, y, { title = '', subtitle = '', extra = [] } = {}) {
  closeQuickMenu();
  const token = S.menuToken;
  const label = describePred(pred);
  const cats = el('div');
  const fill = async () => {
    if (pred.file) return true;
    let c;
    try { c = await api(`/api/categories?pred=${encodeURIComponent(JSON.stringify(pred))}${filterParam()}`); }
    catch (err) { setStatus(err.message); return false; }
    const check = (p, name, n, shown) => {
      const row = el('label', { class: 'menu-check', 'data-pred': JSON.stringify(p), title: rowTitle(p, shown, n, name) },
                     filterBox(p, shown, n), el('span', {}, name), el('span', { class: 'n' }, countText(shown, n)));
      row.querySelector('input').addEventListener('change', async () => { await S.filterApplying; await fill(); });
      return row;
    };
    const rows = [];
    if (!pred.tool && c.types.length) {
      rows.push(el('div', { class: 'menu-group' }, `Evidence types in ${label}`),
                ...c.types.map((t) => check({ ...pred, tool: t.tool, artifact: t.artifact }, `${t.artifact} (${toolName(t.tool)})`, t.count, t.shown)));
    }
    if (!pred.channel && c.channels.length) {
      const top = c.channel_total > c.channels.length ? `, top ${c.channels.length} of ${c.channel_total}` : '';
      rows.push(el('div', { class: 'menu-group' }, `Event log channels in ${label}${top}`),
                ...c.channels.map((ch) => check({ ...pred, channel: ch.channel }, ch.channel, ch.count, ch.shown)));
      if (top) rows.push(menuItem(`All ${c.channel_total} channels in the Sources panel`, () => openFilterPanelAt(pred)));
    }
    cats.replaceChildren(...(rows.length ? [el('hr'), ...rows] : []));
    return true;
  };
  await fill();
  if (token !== S.menuToken) return;
  const sections = [[menuItem(`Show only ${label}`, () => showOnly(pred)), menuItem(`Hide ${label}`, () => setShown(pred, false))]];
  const menu = $('quickMenu');
  menu.setAttribute('aria-label', 'Item actions');
  menu.replaceChildren(el('div', { class: 'menu-head' }, el('div', {}, title || label), ...(subtitle ? [el('div', { class: 'muted' }, subtitle)] : [])),
                       ...sections[0], cats,
                       ...extra.filter((items) => items.length).flatMap((items) => [el('hr'), ...items]));
  placeMenu(x, y);
  const first = menu.querySelector('button:not([disabled])');
  if (first) first.focus();
}
