import { clockBadges } from './clock.js';
import { $, api, el, KEY_LABEL, LANE_FOLDS_CASES, LANE_FOLDS_KEY, MARK_ORDER, OUTSIDE_GROUP, S } from './core.js';
import { refreshViewStatus } from './data.js';
import { refreshDivider } from './dividers.js';
import { draw } from './draw.js';
import { filterParam } from './filters.js';
import { guessBadge } from './hosts.js';
import { countShown, renderStateLine } from './state_line.js';
import { tacticOrder } from './tags.js';

// ---------- lanes ----------

export function compareLanes(a, b) {
  for (let d = 0; d < S.groupby.length; d++) {
    const x = a.keys[d], y = b.keys[d];
    if (x === y) continue;
    if (S.groupby[d] === 'mark') return MARK_ORDER.indexOf(x) - MARK_ORDER.indexOf(y);
    if (S.groupby[d] === 'tactic') return tacticOrder(x) - tacticOrder(y);   // kill-chain order, Untagged last
    return String(x).localeCompare(String(y));
  }
  return 0;
}

export function buildTree() {
  const root = { id: '[]', children: [] };
  const nodes = new Map();
  if (S.meta.outside_sources.length) {
    const group = { id: OUTSIDE_GROUP, label: 'Sources outside the case', depth: 0, children: [], count: null };
    root.children.push(group);
    for (const ip of S.meta.outside_sources) group.children.push({ id: 'out:' + ip, label: ip, depth: 1, children: [], outside: ip });
  }
  for (const lane of [...S.lanes].sort(compareLanes)) {
    let parent = root;
    for (let d = 0; d < lane.keys.length; d++) {
      const keys = lane.keys.slice(0, d + 1);
      const id = JSON.stringify(keys);
      let node = nodes.get(id);
      if (!node) {
        // A user lane keys on the account's lower-case name and shows its usual spelling
        const label = (S.laneNames[S.groupby[d]] || {})[keys[d]] ?? String(keys[d]);
        node = { id, label, depth: d, children: [], count: 0, keys, key: S.groupby[d] };
        nodes.set(id, node);
        parent.children.push(node);
      }
      node.count += lane.count;
      parent = node;
    }
  }
  S.tree = root;
}

// ---------- folds ----------
// A first-level group is folded unless the analyst opened it, and a deeper group is open unless the analyst folded it, so
// the page opens on the first level and opening Malicious shows everything under it. The choices are kept by case and
// preset in this browser (LANE_FOLDS_KEY), for the LANE_FOLDS_CASES cases used last, and in the page while storage is
// blocked. The case is named by /api/meta's case_key, a hash of its folder, since case_id changes with every open. A
// group that appears later, such as Malicious after the first mark, has no choice and opens folded.

let foldStore = null;   // { cases: [{ key, presets: { 'mark,role,host': { id: true for open, false for folded } } }] }, used last first

function readFoldStore() {
  if (foldStore) return foldStore;
  let cases = [];
  try {
    const parsed = JSON.parse(localStorage.getItem(LANE_FOLDS_KEY) || '{}');
    if (Array.isArray(parsed.cases)) {
      cases = parsed.cases.filter((c) => c && typeof c.key === 'string' && c.presets && typeof c.presets === 'object');
    }
  } catch (_) { /* storage blocked, or not what this page wrote */ }
  foldStore = { cases };
  return foldStore;
}

const presetKey = () => S.groupby.join(',');

// The store written back, this case first, so the 20 cases kept are the ones used last
function writeFoldStore(store, entry) {
  store.cases = [entry, ...store.cases.filter((c) => c !== entry)].slice(0, LANE_FOLDS_CASES);
  try { localStorage.setItem(LANE_FOLDS_KEY, JSON.stringify(store)); } catch (_) { /* storage blocked: the page keeps it */ }
}

// This case's choices for the current preset, read on open and on a preset change. A read is a use: the case moves to
// the front, so a case only looked at isn't the first to go.
export function loadFolds() {
  const store = readFoldStore();
  const entry = store.cases.find((c) => c.key === S.meta.case_key);
  if (entry && store.cases[0] !== entry) writeFoldStore(store, entry);
  const choices = entry && entry.presets[presetKey()];
  S.foldChoices = new Map(choices && typeof choices === 'object' ? Object.entries(choices).map(([id, open]) => [id, !!open]) : []);
}

function saveFolds() {
  const store = readFoldStore();
  const entry = store.cases.find((c) => c.key === S.meta.case_key) || { key: S.meta.case_key, presets: {} };
  entry.presets[presetKey()] = Object.fromEntries(S.foldChoices);
  writeFoldStore(store, entry);
}

export function isFolded(node) {
  const choice = S.foldChoices.get(node.id);
  return choice === undefined ? node.depth === 0 : !choice;
}

function setFolds(choices) {
  S.foldChoices = choices;
  saveFolds();
  layoutRows();
  const note = S.linkNote;
  draw();
  if (S.linkNote !== note) refreshViewStatus();   // a fold can hide logon links, and an open can show them: the note says
}
const setFold = (node, open) => setFolds(new Map(S.foldChoices).set(node.id, open));
const anyOpen = () => S.rows.some((row) => row.children.length > 0 && !isFolded(row));
// Open all opens every group: the first level by choice, the rest by default. Fold all is the default again.
export const openAll = () => setFolds(new Map(S.tree.children.filter((n) => n.children.length > 0).map((n) => [n.id, true])));
export const foldAll = () => setFolds(new Map());
export const toggleAll = () => (anyOpen() ? foldAll() : openAll());

// The toolbar's button beside Lanes: Open all while every group is folded, Fold all once any is open
function renderFoldButton() {
  const button = $('foldAll');
  button.hidden = !S.rows.some((row) => row.children.length > 0);
  button.textContent = anyOpen() ? 'Fold all' : 'Open all';
}

export function layoutRows() {
  S.rows = [];
  S.rowIndex = new Map();
  const walk = (node) => {
    for (const child of node.children) {
      S.rowIndex.set(child.id, S.rows.length);
      S.rows.push(child);
      if (!isFolded(child)) walk(child);
    }
  };
  walk(S.tree);
  const labels = $('labels');
  labels.replaceChildren(...S.rows.map((row, i) => {
    const isGroup = row.children.length > 0;
    const div = el('div', { class: isGroup ? 'row group' : 'row', title: row.key ? `${KEY_LABEL[row.key]}: ${row.label}` : row.label });
    div.style.paddingLeft = `${4 + row.depth * 14}px`;
    div.append(el('span', { class: 'twisty' }, isGroup ? (isFolded(row) ? '▸' : '▾') : ''), row.label);
    if (row.count != null) div.append(el('span', { class: 'count' }, row.count.toLocaleString()));
    const guess = guessBadge(row);
    if (guess) div.append(guess);
    div.append(...clockBadges(row));   // how far the host's clock ran from the capture's
    div.dataset.row = String(i);
    if (isGroup) div.addEventListener('click', () => setFold(row, isFolded(row)));
    return div;
  }));
  renderFoldButton();
}

// The visible row for a lane: the lane itself, or its nearest folded ancestor.
export function rowOfKeys(keys) {
  for (let d = keys.length; d >= 1; d--) {
    const row = S.rowIndex.get(JSON.stringify(keys.slice(0, d)));
    if (row !== undefined) return row;
  }
  return undefined;
}

// A link's source row: the source host's lane that shares the most keys with the target lane.
export function sourceRow(host, targetKeys, hostIdx) {
  let best, bestScore = -1;
  for (const lane of S.lanes) {
    if (lane.keys[hostIdx] !== host) continue;
    const score = lane.keys.reduce((n, k, i) => n + (i !== hostIdx && k === targetKeys[i] ? 1 : 0), 0);
    if (score > bestScore) { best = lane; bestScore = score; }
  }
  return best ? rowOfKeys(best.keys) : undefined;
}

export async function reloadLanes() {
  const res = await api(`/api/lanes?groupby=${S.groupby.join(',')}${filterParam()}`);
  S.lanes = res.lanes;
  S.laneNames = res.names || {};
  // The state line's counts, for the filter this answer applied; what the lanes can't count follows
  S.lanesShown = res.shown;
  S.machineLinks = res.machine_links;
  S.laneSet = new Set(res.lanes.map((l) => JSON.stringify(l.keys)));
  buildTree();
  layoutRows();
  refreshDivider();   // the default split follows the first-level rows
  countShown();
  renderStateLine();
}
