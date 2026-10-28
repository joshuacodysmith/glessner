// The page after a reload. F5 in the same tab, while the server still has the same
// open of the case, comes back to the path's step, the Details page, the selection and the event in focus with the pivot
// trail, the search box's text, the Lanes preset, and the timeline's window. On the Findings page it also comes back to
// the open finding forms, new or an edit, as they were typed, and the report summary's unsaved text; a saved finding or
// summary leaves none to bring back. When the Findings page can't draw them, as its read failed or another page came
// first, they wait for its next draw, through further reloads on any step. Every other load opens on the
// Case overview: a new tab from the printed link (sessionStorage is the tab's own), a new serve run or another open of the
// case (each has its own open ID, /api/meta's case_id), and a link or an address opened in the same tab, which is a
// navigation and not a reload. The Sources and View filters start off, as on every load, and the status line says so
// when they were on. The window isn't put back when the case had no events, nor when it lies wholly before the case's
// first event or after its last, as after a load that moves them all elsewhere in time: the reload opens on the
// address's window, or fits the events.

import { showAudit } from './audit.js';
import { $, LISTED_EVENTS, S } from './core.js';
import { draw } from './draw.js';
import { claimDetails, fillFocusEvent, loadDetails } from './event_page.js';
import { filterCount } from './filters.js';
import { findingsDraft, keepFindingsDraft, showFindings } from './findings.js';
import { behindOverview, markTab } from './frame.js';
import { showImport } from './import.js';
import { pivot, showInvestigate, showRules } from './pages.js';
import { showSearch, showSearchHelp } from './search.js';
import { showSuggestions, shownSuggestions } from './suggestions.js';
import { showTools } from './tools.js';
import { viewCount } from './view.js';

const PLACE_KEY = 'glessner.place';
// The path's steps that are a Details page of their own, and the pages drawn with no arguments. Findings gives how many
// of its draft's edit forms it couldn't open again.
const TAB_PAGES = { investigate: showInvestigate, findings: showFindings, audit: () => showAudit() };
const PAGES = { tools: () => showTools(), import: showImport, rules: showRules, searchHelp: showSearchHelp };
// Lists a reload can't draw again: the events under the cursor, and those a Case overview number opened, which read the
// filter the reload drops
const LISTS = ['pile', 'opened'];

// What the Details panel shows, as the reload draws it again; { name: 'list' } for a list it can't, and null for the
// opening hint or a page the path's step draws
function detailsPlace() {
  const panel = $('details'), name = panel.dataset.page, key = panel.dataset.key || '';
  if (name === 'event' && S.focus && key === `event:${S.focus}`) {
    const p = S.pivotResult && S.pivotResult.uid === S.focus ? S.pivotResult : null;   // its list is on the page
    return { name, uid: S.focus, pivot: p && { kind: p.kind, seconds: p.seconds, ip: p.ip, more: p.more || {} } };
  }
  if (name === 'search' && key.startsWith('search:')) return { name, q: key.slice('search:'.length) };
  if (name === 'suggestions' && shownSuggestions()) return { name, ...shownSuggestions() };
  if (Object.hasOwn(PAGES, name)) return { name };
  return LISTS.includes(name) ? { name: 'list' } : null;
}

function place() {
  // A selection longer than a list holds is kept as its event in focus alone, rather than cut to part of it
  const selected = S.selected.size <= LISTED_EVENTS ? [...S.selected] : (S.focus ? [S.focus] : []);
  const view = S.anim ? S.anim.view : S.view;   // where a window still moving is going
  return {
    open: S.meta.case_id, tab: S.tab, preset: Number($('groupby').value) || 0,
    // S.meta.rows is the count when this page opened. A page opened on a case with no events keeps no window, even after
    // a load brings events and reloads it: fit() gave it 2 s around time 0, with nothing on the timeline
    view: S.meta.rows ? { start: view.start, end: view.end } : null,
    focus: S.focus, selected, trail: S.trail, trailAt: S.trailAt,
    details: detailsPlace(), draft: findingsDraft(), search: $('search').value,
    filtered: { sources: filterCount() > 0, view: viewCount() > 0 },
  };
}

// Saved as the page goes, which a reload, a closed tab, and a navigation all pass through
export function keepPlace() {
  window.addEventListener('pagehide', () => {
    try { sessionStorage.setItem(PLACE_KEY, JSON.stringify(place())); } catch (_) { /* storage blocked: the reload opens the overview */ }
  });
}

// The place this tab saved, when this load is a reload of the same open of the case; otherwise null.
export function savedPlace() {
  let saved = null;
  try {
    const nav = performance.getEntriesByType('navigation')[0];
    if (nav && nav.type === 'reload') saved = JSON.parse(sessionStorage.getItem(PLACE_KEY) || 'null');
  } catch (_) { return null; /* storage blocked, or not JSON */ }
  const tabs = ['overview', 'timeline', ...Object.keys(TAB_PAGES)];
  if (!saved || typeof saved !== 'object' || saved.open !== S.meta.case_id || !tabs.includes(saved.tab)) return null;
  const { start, end } = saved.view || {};
  // Whether the window, which takes in its start and not its end, shows any of the span from the case's first event to
  // its last; the span is in microseconds where the window is in milliseconds, and a case with no events has none
  const shows = S.meta.start != null && start <= S.meta.end / 1000 && end > S.meta.start / 1000;
  return { ...saved, view: Number.isFinite(start) && Number.isFinite(end) && start < end && shows ? saved.view : null,
           preset: Number.isInteger(saved.preset) && S.meta.presets[saved.preset] ? saved.preset : null };
}

// Put the place back, once the lanes have loaded and the window is set (main.init), and return the status line's words.
// The Details page is drawn behind the overview when the overview was up, so the Timeline step shows it again.
export async function restorePlace(saved) {
  S.selected = new Set(Array.isArray(saved.selected) ? saved.selected : []);
  S.focus = typeof saved.focus === 'string' ? saved.focus : null;
  if (S.focus) S.selected.add(S.focus);
  if (Array.isArray(saved.trail)) {
    S.trail = saved.trail;
    S.trailAt = Number.isInteger(saved.trailAt) && saved.trailAt < S.trail.length ? saved.trailAt : S.trail.length - 1;
  }
  if (typeof saved.search === 'string') $('search').value = saved.search;
  if (saved.draft) keepFindingsDraft(saved.draft);
  draw();
  const details = saved.details || {};
  // The page the Details panel had in place of the event's, or null when the event in focus draws its own
  const page = details.name === 'search' ? () => showSearch(details.q)
    : details.name === 'suggestions' ? () => showSuggestions(details.source, details.groupBy || '', details.limit || 0)
    : Object.hasOwn(PAGES, details.name) ? PAGES[details.name] : null;
  const drawDetails = async () => {
    if (page) await page();
    else if (S.focus) {
      await loadDetails(S.focus);
      const p = details.name === 'event' && details.uid === S.focus ? details.pivot : null;
      if (p) await pivot(S.focus, p.kind, p.seconds, p.ip, p.more, true);
    }
  };
  // Pages that name the event in focus, such as Findings' New finding, read it as its Event page left it; when the reload
  // draws another page, the event is read here first, without drawing its page. The read claims the panel for the page
  // the reload draws, so a page asked for during it, such as an event clicked on the timeline, keeps the panel.
  let latest = () => true;
  if (S.focus && (page || Object.hasOwn(TAB_PAGES, saved.tab))) {
    latest = claimDetails();
    await fillFocusEvent(S.focus);
  }
  let retired = 0;   // edit forms of findings retired since the page was left, which can't open again
  if (latest()) {
    if (Object.hasOwn(TAB_PAGES, saved.tab)) retired = (await TAB_PAGES[saved.tab]()) || 0;
    else if (saved.tab === 'overview') await behindOverview(drawDetails);
    else {
      markTab('timeline');
      await drawDetails();
    }
  }
  const words = ['Back where the page was before the reload.'];
  if (details.name === 'list') words.push('Its list of events is not kept across a reload.');
  if (retired) {
    words.push(retired === 1 ? 'The finding being edited was retired, so its changes are not kept.'
      : `${retired} findings being edited were retired, so their changes are not kept.`);
  }
  const { sources, view } = saved.filtered || {};
  if (sources || view) {
    const which = sources && view ? 'the Sources and View filters' : sources ? 'the Sources filter' : 'the View filter';
    words.push(`The reload turned ${which} off, as every load does.`);
  }
  return words.join(' ');
}
