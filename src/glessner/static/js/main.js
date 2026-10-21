// Glessner's timeline page. Draws nested lanes on a canvas: density when zoomed out, single
// events when zoomed in, and logon links between host lanes. Event text comes from collected
// evidence, so it is only ever inserted with textContent, never as HTML.
// Entry module: index.html loads it, and its imports bring in the rest.

import { alignClocks, renderClockSwitch } from './clock.js';
import { $, api, el, KEY_LABEL, LABELS_MIN_PX, plural, reportAction, S, setStatus } from './core.js';
import { refreshCounts } from './counts.js';
import { animateView, fetchView, fitTitle, scheduleFetch, setView } from './data.js';
import { setupDivider, setupLabelDivider } from './dividers.js';
import { draw } from './draw.js';
import { renderFilterState, toggleFilterPanel } from './filters.js';
import { markTab, setupFrame, showTab } from './frame.js';
import { showImport } from './import.js';
import { select, setupCanvas } from './interaction.js';
import { loadFolds, reloadLanes, toggleAll } from './lanes.js';
import { setupLegend } from './legend.js';
import { jumpTo } from './pages.js';
import { keepPlace, restorePlace, savedPlace } from './place.js';
import { setupQuickMenu } from './quick_menu.js';
import { setupSearch } from './search.js';
import { machineChanged } from './state_line.js';
import { showTools } from './tools.js';
import { renderViewState, toggleViewPanel } from './view.js';
import { openZoneMenu, renderZoneAxes } from './zones.js';

// ---------- start ----------

export function resize() {
  // The lane labels get the width the analyst chose, as far as the Timeline panel allows; opening the Filter
  // panel narrows them, and closing it gives the chosen width back.
  const w = clampLabels(S.labelWant);
  if (w !== S.labelW) {
    S.labelW = w;
    document.documentElement.style.setProperty('--label-w', `${w}px`);
  }
  S.width = Math.max(200, $('scroller').clientWidth - S.labelW - 2);
  draw();
}

export const clampLabels = (w) => Math.round(Math.min(Math.max(w, LABELS_MIN_PX), Math.max(LABELS_MIN_PX, $('timeline').clientWidth - 300)));

export async function init() {
  S.meta = await api('/api/meta');
  // ?start=...&end=... (ISO 8601 UTC) opens a specific window, for example one noted in a report; ?page=tools or
  // ?page=import opens that page, as a new case from the start page does. Otherwise a case with events opens on its
  // overview, unless this load is a reload of the same open in this tab, which comes back to the page as
  // it was (place.js).
  const params = new URLSearchParams(location.search);
  const from = Date.parse(params.get('start') || ''), to = Date.parse(params.get('end') || '');
  const page = params.get('page');
  const saved = savedPlace();
  const overviewFirst = saved ? saved.tab === 'overview' : !page && !(from < to) && S.meta.rows > 0;
  $('caseName').textContent = $('caseName').title = S.meta.case;   // the name ellipsizes in a narrow header
  const presetSelect = $('groupby');
  presetSelect.replaceChildren(...S.meta.presets.map((p, i) => el('option', { value: String(i) }, p.map((k) => KEY_LABEL[k]).join(' > '))));
  if (saved && saved.preset !== null) {
    presetSelect.value = String(saved.preset);
    S.groupby = S.meta.presets[saved.preset];
  }
  presetSelect.addEventListener('change', async () => {
    S.groupby = S.meta.presets[Number(presetSelect.value)];
    loadFolds();   // each preset keeps its own folds
    await reloadLanes();
    draw();
    fetchView();
  });
  $('foldAll').addEventListener('click', toggleAll);
  // The Case panel's path and Case menu, and the hover hints. The overview shows first, and the timeline
  // loads behind it once the overview has answered: asked for together, each takes longer.
  setupFrame();
  const opening = overviewFirst ? showTab('overview') : null;
  $('showLinks').addEventListener('change', () => { draw(); fetchView(); });   // the view carries links only when shown
  $('hideMachine').addEventListener('change', machineChanged);
  $('fit').addEventListener('click', () => fit(true));
  fitTitle();
  // Host times as recorded, or aligned to the capture; shown once a clock is measured.
  $('clockRecorded').addEventListener('click', () => { if (S.meta.clock_alignment !== 'recorded') alignClocks('recorded'); });
  $('clockAligned').addEventListener('click', () => { if (S.meta.clock_alignment !== 'aligned') alignClocks('capture'); });
  renderClockSwitch();
  $('filtersButton').addEventListener('click', () => toggleFilterPanel());
  $('viewButton').addEventListener('click', () => toggleViewPanel());
  setupSearch();
  renderFilterState();
  renderViewState();
  setupLegend();
  setupCanvas();
  setupQuickMenu();
  setupDivider();
  setupLabelDivider();
  S.zones = S.meta.time_zones || [];
  renderZoneAxes();
  $('addZone').addEventListener('click', (ev) => { const r = ev.currentTarget.getBoundingClientRect(); openZoneMenu(r.left, r.bottom + 2); });
  if (opening) await opening;
  loadFolds();   // the groups this browser opened or folded in this case, for this preset
  await reloadLanes();
  refreshCounts();
  resize();
  if (saved && saved.view) await setView(saved.view.start, saved.view.end);
  else if (from < to) await setView(from, to); else await fit();
  const orphans = S.meta.orphan_marks;
  const orphanWarning = orphans ? `Warning: ${plural(orphans, 'mark')} ${orphans === 1 ? 'refers to an event that no longer exists'
                                                                                  : 'refer to events that no longer exist'}.` : '';
  if (orphanWarning) reportAction(orphanWarning);   // after the first redraw, so it is the line's action; no server time
  // A case without events yet starts on the Tools page, which runs the tools that load them.
  if (saved) {
    let words;
    try { words = await restorePlace(saved); } catch (err) { words = `The reload could not put the page back: ${err.message}`; }
    reportAction(orphanWarning ? `${orphanWarning} ${words}` : words);
  } else if (page === 'import') showImport();
  else if (page === 'tools' || !S.meta.rows) showTools();
  else if (!overviewFirst) markTab('timeline');
  if (!S.meta.rows) {   // set whole: this line would replace the warning above
    const none = 'No events yet. Run tools from the Tools page, or bring in logs from the Import page.';
    setStatus(orphanWarning ? `${orphanWarning} | ${none}` : none);
  }
  // The browser window, the divider, the Hosts panel, and the timeline's own scrollbar can each change its width.
  let lastWidth = $('scroller').clientWidth;
  // Redraw on the next frame, not inside the observer: lanes appearing or going can toggle the scrollbar, and a
  // redraw within the same layout pass makes the browser report a ResizeObserver loop.
  new ResizeObserver(() => requestAnimationFrame(() => {
    const w = $('scroller').clientWidth;
    if (w === lastWidth) return;
    lastWidth = w;
    resize();
    scheduleFetch();
  })).observe($('scroller'));
  keepPlace();
  window.__app = { S, setView, draw, fetchView, select, jumpTo, showTab };   // hooks for browser tests
  window.__ready = true;
}

export async function fit(animate = false) {
  const f = S.meta.fit || {};
  const start = (f.start ?? S.meta.start) / 1000, end = (f.end ?? S.meta.end) / 1000;
  const pad = Math.max((end - start) * 0.02, 1000);
  await (animate ? animateView : setView)(start - pad, end + pad);
}

init().catch((err) => setStatus(`Could not start: ${err.message}`));
