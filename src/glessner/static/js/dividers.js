import { $, DETAILS_KEY, DETAILS_MIN_PX, DETAILS_SHARE, LABEL_W, LABELS_KEY, LABELS_MIN_PX, OLD_DETAILS_KEYS, ROW_H, S, TIMELINE_MIN_PX } from './core.js';
import { scheduleFetch } from './data.js';
import { clampLabels, resize } from './main.js';

// ---------- divider between the Timeline panel and the Details panel ----------

let redraw = null;   // the divider's show(), for a refresh after the lanes reload (refreshDivider)

export function setupDivider() {
  const divider = $('divider'), details = $('details'), stage = $('stage');
  // The panel opens at two-thirds of the stage, the panel area, unless that leaves the Timeline too short to show every
  // first-level row of the preset folded; then it takes what is left, and never under half the stage (on
  // Szechuan at 1280 by 720, two-thirds leaves 56 px of lanes for seven groups). The
  // stage is the Timeline, the divider, and the Details panel, so opening the Hosts panel shrinks both. A height the
  // analyst sets is kept as its share of the stage, so the split holds when the window changes size.
  // Leave the Timeline panel at least TIMELINE_MIN_PX below the Case panel and the Hosts panel, but never
  // let the limit fall below the minimum: a hidden or tiny window can report a height near 0.
  const maxHeight = () => {
    const below = window.innerHeight - $('timeline').getBoundingClientRect().top;
    return Math.max(DETAILS_MIN_PX, below - TIMELINE_MIN_PX - divider.offsetHeight - 12);
  };
  const clamp = (h) => Math.round(Math.min(Math.max(h, DETAILS_MIN_PX), maxHeight()));
  // What the Timeline needs to show the first-level rows folded: its toolbar, state line, and axis row as drawn, the
  // rows, and the margins and borders around them, measured from the layout on screen (the stage less the panel, the
  // divider, and the Timeline's four parts), so they follow the stylesheet. The rows are counted from the tree's root,
  // whatever the analyst has opened, so the default doesn't move as groups open.
  const defaultHeight = () => {
    const two = Math.round(stage.clientHeight * DETAILS_SHARE);
    const rows = S.tree ? S.tree.children.length : 0;
    if (!rows) return two;
    const fixed = $('tlToolbar').offsetHeight + $('stateLine').offsetHeight + $('axisRow').offsetHeight;
    const around = stage.clientHeight - details.offsetHeight - divider.offsetHeight - fixed - $('scroller').clientHeight;
    const left = stage.clientHeight - divider.offsetHeight - around - fixed - rows * ROW_H;
    return Math.round(Math.max(stage.clientHeight / 2, Math.min(two, left)));
  };
  // The share the analyst chose, or null for the default. A smaller window shows less of it, and growing the window
  // restores it. The older keys held pixels, the old defaults among them, so each is dropped, not read.
  let share = null;
  try {
    for (const key of OLD_DETAILS_KEYS) localStorage.removeItem(key);
    const stored = Number(localStorage.getItem(DETAILS_KEY));
    if (Number.isFinite(stored) && stored > 0 && stored < 1) share = stored;
  } catch (_) { /* storage blocked */ }
  const shown = () => clamp(share === null ? defaultHeight() : Math.round(share * stage.clientHeight));
  const show = () => { details.style.flexBasis = `${shown()}px`; };
  const set = (h) => {
    const height = clamp(h);
    // Not a share of a hidden or tiny stage, which can't hold both panels' minimums
    if (stage.clientHeight >= DETAILS_MIN_PX + TIMELINE_MIN_PX) share = height / stage.clientHeight;
    show();
  };
  const save = () => {
    if (window.innerHeight < 300) return;   // don't remember a size taken while the window was hidden or tiny
    try {
      if (share === null) localStorage.removeItem(DETAILS_KEY); else localStorage.setItem(DETAILS_KEY, share.toFixed(4));
    } catch (_) { /* storage blocked */ }
  };
  redraw = show;
  show();
  // The window, the Hosts panel, and the Case panel's rows all resize the stage; the toolbar and the state line change
  // height when they wrap, and the default follows
  const watch = new ResizeObserver(show);
  for (const id of ['stage', 'tlToolbar', 'stateLine', 'axisRow']) watch.observe($(id));
  let dragging = false;
  divider.addEventListener('mousedown', (ev) => { dragging = true; document.body.classList.add('resizing'); ev.preventDefault(); });
  window.addEventListener('mousemove', (ev) => {
    if (dragging) set(window.innerHeight - ev.clientY - 12);   // 12 px: the Details panel's bottom margin
  });
  window.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    document.body.classList.remove('resizing');
    save();
  });
  divider.addEventListener('dblclick', () => { share = null; show(); save(); });
  divider.addEventListener('keydown', (ev) => {
    const step = ev.shiftKey ? 80 : 20;
    if (ev.key === 'ArrowUp') { set(shown() + step); save(); ev.preventDefault(); }
    if (ev.key === 'ArrowDown') { set(shown() - step); save(); ev.preventDefault(); }
  });
}

// The default split follows the first-level rows, so the lanes' reload asks for it again
export function refreshDivider() {
  if (redraw) redraw();
}

// ---------- divider between the lane labels and the canvas ----------

export function setupLabelDivider() {
  const divider = $('labelDivider'), main = $('timeline');
  const apply = (w, save) => {
    S.labelWant = clampLabels(w);
    resize();
    if (!save) return;
    try { localStorage.setItem(LABELS_KEY, String(S.labelWant)); } catch (_) { /* storage blocked */ }
    scheduleFetch();   // the canvas width changed, so the density buckets did too
  };
  let stored = 0;
  try { stored = Number(localStorage.getItem(LABELS_KEY)); } catch (_) { /* storage blocked */ }
  apply(Number.isFinite(stored) && stored >= LABELS_MIN_PX ? stored : LABEL_W, false);
  let dragging = false;
  divider.addEventListener('mousedown', (ev) => {
    dragging = true;
    document.body.classList.add('resizing-labels');
    ev.preventDefault();
  });
  window.addEventListener('mousemove', (ev) => { if (dragging) apply(ev.clientX - main.getBoundingClientRect().left, false); });
  window.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    document.body.classList.remove('resizing-labels');
    apply(S.labelWant, true);
  });
  // Fit the longest label, but leave the canvas at least half the panel; dragging can go further.
  divider.addEventListener('dblclick', () => apply(Math.min(widestLabel(), main.clientWidth / 2), true));
  divider.addEventListener('keydown', (ev) => {
    const step = ev.shiftKey ? 80 : 20;
    if (ev.key === 'ArrowLeft') { apply(S.labelWant - step, true); ev.preventDefault(); }
    if (ev.key === 'ArrowRight') { apply(S.labelWant + step, true); ev.preventDefault(); }
  });
}

// The width that shows every lane label in full: the widest row's content, which ellipsis otherwise cuts.
export function widestLabel() {
  let w = 0;
  for (const row of $('labels').children) w = Math.max(w, row.scrollWidth);
  return w + 16;
}
