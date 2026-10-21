import { $, api, CELL_ZOOM_SHARE, fmtUs, HINTS, renderStatus, S, setStatus, VIEW_ANIM_MS } from './core.js';
import { draw } from './draw.js';
import { filterCount, filterParam } from './filters.js';
import { renderWindow } from './state_line.js';
import { viewNote } from './view.js';

// ---------- data ----------

export function scheduleFetch() {
  clearTimeout(S.timer);
  S.timer = setTimeout(fetchView, 120);
  awaitWindow(S.view);
}

const sameWindow = (a, b) => !!a && !!b && a.start === b.start && a.end === b.end;

// The state line's "In this window" count belongs to the window the drawn data is for: from the moment the window changes it
// reads "…" until that window's data answers.
function awaitWindow(view) {
  if (S.windowPending || sameWindow(view, S.shownWindow)) return;
  S.windowPending = true;
  renderWindow();
}

// One view request at a time. The browser can cancel a request, but the server still runs its query to the end, so
// a burst of canceled requests while zooming delayed the one the analyst waited for: 8.5 s instead of under 1 s on
// a 2-million-event case. A window asked for meanwhile is fetched when the current request
// returns, and the windows passed over in between are skipped.
export let viewRequest = null, nextView = null;
export function fetchView(view = S.view) {
  awaitWindow(view);
  if (!viewRequest) {
    viewRequest = loadView(view).finally(() => { viewRequest = null; });
    return viewRequest;
  }
  if (nextView) { nextView.view = view; return nextView.done; }
  nextView = { view };
  nextView.done = viewRequest.then(() => { const v = nextView.view; nextView = null; return fetchView(v); });
  return nextView.done;
}

export async function loadView(view) {
  const t0 = performance.now();
  const start = Math.floor(view.start * 1000), end = Math.ceil(view.end * 1000);
  const buckets = Math.max(50, Math.floor(S.width / 4));
  // The server resolves logon links only when they're shown.
  const url = `/api/view?start=${start}&end=${end}&buckets=${buckets}&groupby=${S.groupby.join(',')}` +
              `&hide_machine=${$('hideMachine').checked ? 1 : 0}&links=${$('showLinks').checked ? 1 : 0}` +
              `&limit=${S.meta.event_threshold}${filterParam()}${fitInView(view) ? '&outside=1' : ''}`;
  try {
    const data = await api(url);
    if (nextView) return;   // a newer window is on its way, so this one is already out of date
    const loaded = { data, fetchMs: performance.now() - t0, span_s: (end - start) / 1e6, view };
    if (S.anim && S.anim.view === view) { S.anim.loaded = loaded; return; }   // shown when the motion ends
    showData(loaded);
  } catch (err) {
    S.windowPending = false;
    renderWindow();
    setStatus(`Error: ${err.message}`);
  }
}

export function showData({ data, fetchMs, span_s, view = S.view }) {
  S.data = data;
  S.windowPending = false;
  const drawMs = draw();
  const rec = { mode: data.mode, count: data.count, links: data.links.items.length, linkMode: data.links.mode,
                server_ms: data.server_ms, fetch_ms: Math.round(fetchMs), draw_ms: Math.round(drawMs),
                total_ms: Math.round(fetchMs + drawMs), span_s };
  window.__timings.push(rec);
  // A window the drawn data wasn't for is itself the last action; a redraw of the same window keeps the earlier one, so a
  // mark's line outlasts the redraw that follows it
  if (!sameWindow(view, S.shownWindow)) {
    S.shownWindow = { start: view.start, end: view.end };
    S.lastAction = { text: 'Window moved', ms: data.server_ms };
  }
  refreshViewStatus();
}

// The view's notes on the status line, after the last action: the logon links' note, the Sources, the View, and the
// strays. A redraw that changes the notes without new data, such as a fold that hides links, asks for it too.
export function refreshViewStatus() {
  const data = S.data;
  if (!data) return;
  S.viewStatus = [S.linkNote, filterCount() ? 'Sources filtered' : '', viewNote(data), strayNote(data)].filter(Boolean).join(' | ');
  renderStatus();
}

// How many events lie before and after a range, and from and to when.
function outsideParts({ before, after, first, last }) {
  const parts = [];
  if (before) parts.push(`${before.toLocaleString()} earlier, from ${fmtUs(first).slice(0, 10)}`);
  if (after) parts.push(`${after.toLocaleString()} later, to ${fmtUs(last).slice(0, 10)}`);
  return parts;
}

// Fit case's hover text: the range it shows, and the strays it leaves out. Strays can be
// leads: a timestomped file or a skewed clock.
export function fitTitle() {
  if (!S.meta.fit || S.meta.fit.start == null) { $('fit').title = HINTS.fit; return; }
  const parts = outsideParts(S.meta.fit);
  $('fit').title = `${HINTS.fit} From ${fmtUs(S.meta.fit.start).slice(0, 10)} to ${fmtUs(S.meta.fit.end).slice(0, 10)}` +
    (parts.length ? `. Left out as far from the rest: ${parts.join('; ')}. Zoom out to see them.` : '.');
}

// Whether a window holds Fit case's whole range, on a case where Fit case leaves strays out: then the view asks the
// server what lies outside the window.
function fitInView(view) {
  const f = S.meta.fit || {};
  return !!(f.before || f.after) && view.start * 1000 <= f.start && view.end * 1000 >= f.end;
}

// While Fit case's range is in view, what lies outside the window, as the server counted it for the window drawn and
// the Sources and View filter. Fit case's own counts ignore both, so they would name strays the View hides, and count the
// strays inside the drawn margins twice.
export function strayNote(data) {
  const parts = data.outside ? outsideParts(data.outside) : [];
  return parts.length ? `Outside this view: ${parts.join('; ')}. Zoom out to see them.` : '';
}

// Set the window at once and wait for the data. Used at startup and by the measurement script.
export async function setView(startMs, endMs) {
  cancelAnimation();
  S.view = { start: startMs, end: endMs };
  clearTimeout(S.timer);
  draw();
  await fetchView();
}

export const easeInOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);

// The window part way from one view to another. The scale changes evenly on a log scale, around the one
// time that sits at the same place on screen in both views, so a zoom reads as a zoom.
export function viewAt(from, to, k) {
  const s0 = from.end - from.start, s1 = to.end - to.start;
  if (Math.abs(s0 - s1) <= s0 * 1e-6) {   // same scale: a plain pan
    const start = from.start + (to.start - from.start) * k;
    return { start, end: start + s0 };
  }
  const f = (to.start - from.start) / (s0 - s1);
  const fixed = from.start + f * s0;
  const span = Math.exp(Math.log(s0) + (Math.log(s1) - Math.log(s0)) * k);
  return { start: fixed - f * span, end: fixed - f * span + span };
}

export function cancelAnimation() {
  if (!S.anim) return;
  clearTimeout(S.anim.timer);
  S.anim = null;
  // A request still loading for the motion's window is left to finish; a newer one takes its place on the page.
}

// Move the window to [startMs, endMs] over VIEW_ANIM_MS so the analyst can see how the view changes. The
// new window's data loads during the motion and appears when it ends. A reduced-motion setting skips it.
export function animateView(startMs, endMs) {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return setView(startMs, endMs);
  cancelAnimation();
  clearTimeout(S.timer);
  const from = { ...S.view }, to = { start: startMs, end: endMs };
  const anim = { view: to, loaded: null, timer: null };
  S.anim = anim;
  const loading = fetchView(to);
  const t0 = performance.now();
  return new Promise((resolve) => {
    const finish = () => {
      if (S.anim !== anim) { resolve(); return; }
      clearTimeout(anim.timer);
      S.anim = null;
      S.view = to;
      if (anim.loaded) showData(anim.loaded); else draw();
      loading.then(resolve);
    };
    const frame = () => {
      if (S.anim !== anim) { resolve(); return; }
      const k = (performance.now() - t0) / VIEW_ANIM_MS;
      if (k >= 1) { finish(); return; }
      S.view = viewAt(from, to, easeInOut(k));
      draw();
      requestAnimationFrame(frame);
    };
    anim.timer = setTimeout(finish, VIEW_ANIM_MS + 100);   // ends the motion even when the page draws no frames
    requestAnimationFrame(frame);
  });
}

// A click on a density bar zooms in around the click. The time under the cursor stays under it while the
// bar grows to CELL_ZOOM_SHARE of the timeline width; before, the window jumped to the bar's own span.
// Near an edge the zoom centers a little inward, so the whole bar stays on screen.
// What a click on a hit does. Zoomed out (density mode) every click zooms in: on a density bar, on a grouped
// logon arrow, and on a single arrow, which also selects its logon. Zoomed in, a click selects in place.
export const densityMode = () => !!S.data && S.data.mode === 'density';
export const zooms = (hit) => !!hit && (hit.kind === 'cell' || (hit.kind === 'link' && (!hit.l.uid || densityMode())));

// Zoom in at a click on a grouped arrow as if it were a density bar 4 px wide.
export function zoomAtArrow(px) {
  const span = S.view.end - S.view.start;
  const at = S.view.start + (px / S.width) * span, half = (2 / S.width) * span;
  zoomToCell({ from: (at - half) * 1000, to: (at + half) * 1000 }, px);
}

export function zoomToCell(cell, px) {
  const span = S.view.end - S.view.start;
  const f = px / S.width;
  const at = S.view.start + f * span;
  const next = Math.max((cell.to - cell.from) / 1000 / CELL_ZOOM_SHARE, 1000);
  if (next >= span) return;
  const margin = next * 0.02;
  let start = at - f * next;
  start = Math.min(start, cell.from / 1000 - margin);
  start = Math.max(start, cell.to / 1000 + margin - next);
  animateView(start, start + next);
}
