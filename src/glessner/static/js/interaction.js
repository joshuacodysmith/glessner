import { $, codePrefix, cut, DRAG_THRESHOLD_PX, el, fmtUs, HIT_PX, markBadge, markState, plural, ROW_H, S, WHEEL_MAX_PX, WHEEL_PX_PER_DOUBLING, WHEEL_UNIT_PX } from './core.js';
import { cancelAnimation, densityMode, scheduleFetch, zoomAtArrow, zooms, zoomToCell } from './data.js';
import { draw } from './draw.js';
import { claimDetails, loadDetails, setPage } from './event_page.js';
import { showHint } from './frame.js';
import { jumpTo, listFind } from './pages.js';
import { openQuickMenu } from './quick_menu.js';

// ---------- interaction ----------

const HIT_REACH_PX = 5;   // a tick this far from the pointer or more is not a hit

// The tick nearest the pointer. Of two at the same distance, such as two events at one timestamp, the later in the lane's
// index wins: it is drawn last, so it is the one on top, and the menu names what the analyst sees. Keeping
// the first would name the one underneath.
export function hitTest(mx, my) {
  const row = Math.floor(my / ROW_H);
  const items = S.index[row] || [];
  let best = null, bestDist = HIT_REACH_PX;
  for (const item of items) {
    if (item.kind === 'cell') continue;
    const dist = Math.abs(item.x - mx);
    if (dist < HIT_REACH_PX && dist <= bestDist) { best = item; bestDist = dist; }
  }
  // A tick under the cursor wins over a logon arrow that only passes through its lane.
  if (best && bestDist <= HIT_PX) return best;
  for (const seg of S.linkSegs) {
    if (Math.abs(seg.x - mx) <= 4 && my >= seg.y1 - 2 && my <= seg.y2 + 2) return { kind: 'link', l: seg.l };
  }
  for (const item of items) {
    if (item.kind === 'cell' && mx >= item.x0 && mx <= item.x1) return item;
  }
  return best;
}

export const KIND_CUT = 60;   // characters of a tick's kind that the tooltip's and the menu's first lines keep

// What a tick is called in the tooltip: its event code and the first part of its message, as the lists word it.
export function tickKind(e) {
  return cut(`${codePrefix(e)}${String(e.msg ?? '').split(' | ')[0]}`.trim(), KIND_CUT);
}

// The host a tick belongs to: its lane key when the lanes are grouped by host, otherwise the label of the lane it is in.
function tickHost(e, row) {
  const at = S.groupby.indexOf('host');
  return at >= 0 && e.keys ? e.keys[at] : (S.rows[row] ? S.rows[row].label : '');
}

// The tooltip's content as nodes: an event leads with its review state, kind, and host on one line, and the
// time and message under it. The state is a word, so it has no badge. A density bar and a logon arrow keep their text.
export function describe(hit, row = -1) {
  if (hit.kind === 'event') {
    const e = hit.e;
    return [el('div', { class: 'l1' }, `${markState(e.mark).word} · ${tickKind(e)} · ${tickHost(e, row)}`),
            `${fmtUs(e.ts)} UTC · ${e.msg}${e.hit >= 3 ? ' · Hayabusa hit' : ''}`];
  }
  if (hit.kind === 'cell') return [`${plural(hit.count, 'event')}\n${fmtUs(hit.from)} to ${fmtUs(hit.to)} UTC` +
                                   (hit.hit >= 3 ? '\nIncludes a Hayabusa hit at medium or above' : '') + '\nClick to zoom in'];
  const l = hit.l;
  const who = l.accounts ? l.accounts.join(', ') : l.account;
  const when = l.count > 1 ? `${fmtUs(l.ts)} UTC, the middle one` : `${fmtUs(l.ts)} UTC`;
  const kinds = l.kinds ? l.kinds.join(', ') : `${l.kind}, source by ${l.via}`;
  return [`${l.source} -> ${l.target}${l.count > 1 ? ` (${l.count} logons)` : ''}\n${who}\n${kinds}\n${when}` +
          (!l.uid ? '\nClick to zoom in' : densityMode() ? '\nClick to select this logon and zoom in to it' : '')];
}

// What a wheel event multiplies the window's span by: more than 1 zooms out. It follows how far the wheel moved, so a
// touchpad's many small steps and a mouse wheel's notches zoom in proportion. A fixed 1.25 or 0.8 per
// event would zoom ten touchpad steps of 4 px in ninefold and a 1,000 px spin by 0.8.
export function wheelFactor(ev) {
  const px = ev.deltaY * (WHEEL_UNIT_PX[ev.deltaMode] ?? 1);
  return 2 ** (Math.max(-WHEEL_MAX_PX, Math.min(px, WHEEL_MAX_PX)) / WHEEL_PX_PER_DOUBLING);
}

export function setupCanvas() {
  const canvas = $('lanes');
  const tip = $('tooltip');
  canvas.addEventListener('wheel', (ev) => {
    ev.preventDefault();
    cancelAnimation();
    const rect = canvas.getBoundingClientRect();
    const frac = (ev.clientX - rect.left) / S.width;
    const span = S.view.end - S.view.start;
    const at = S.view.start + frac * span;
    const full = (S.meta.end - S.meta.start) / 1000;
    const next = Math.min(Math.max(span * wheelFactor(ev), 1000), Math.max(full * 2, 60000));
    S.view = { start: at - frac * next, end: at - frac * next + next };
    draw();
    scheduleFetch();
  }, { passive: false });
  canvas.addEventListener('mousedown', (ev) => {
    if (ev.button !== 0) return;   // the right button opens the quick-action menu and never selects or pans
    cancelAnimation();
    S.drag = { x: ev.clientX, at: [ev.offsetX, ev.offsetY], view: { ...S.view }, moved: false };
    canvas.style.cursor = '';
    canvas.classList.add('dragging');
  });
  window.addEventListener('mousemove', (ev) => {
    if (S.drag) {
      const dx = ev.clientX - S.drag.x;
      // A press only becomes a pan past the threshold, so a click that wobbles a pixel or two
      // selects without moving the window.
      if (!S.drag.moved && Math.abs(dx) < DRAG_THRESHOLD_PX) return;
      S.drag.moved = true;
      const shift = (dx / S.width) * (S.drag.view.end - S.drag.view.start);
      S.view = { start: S.drag.view.start - shift, end: S.drag.view.end - shift };
      draw();
      tip.hidden = true;
      return;
    }
    if (ev.target !== canvas) { tip.hidden = true; return; }
    const hit = hitTest(ev.offsetX, ev.offsetY);
    // The open hand means drag to pan. An arrow marks something to click; a magnifier, a bar that zooms in.
    canvas.style.cursor = !hit ? '' : zooms(hit) ? 'zoom-in' : 'default';
    if (!hit) { tip.hidden = true; return; }
    tip.replaceChildren(...describe(hit, Math.floor(ev.offsetY / ROW_H)));
    tip.style.left = `${Math.min(ev.clientX + 14, window.innerWidth - 540)}px`;
    tip.style.top = `${ev.clientY + 14}px`;
    tip.hidden = false;
  });
  window.addEventListener('mouseup', (ev) => {
    if (!S.drag) return;
    const drag = S.drag;
    S.drag = null;
    canvas.classList.remove('dragging');
    if (drag.moved) { scheduleFetch(); return; }
    // Hit-test where the press landed, which is where the analyst aimed, not where a wobble let go.
    const [px, py] = drag.at;
    const hit = hitTest(px, py);
    if (hit && hit.kind === 'event') {
      // Dense lanes (MFT especially) stack many events on the same pixels: offer them all. A plain click starts a new
      // selection, as a click on one event does, so an earlier selection can't join the next shift-click unseen. A
      // shift-click keeps it, so a pick from the list can join it; the hit test's first event isn't added instead.
      const under = eventsNear(px, py);
      if (under.length > 1) {
        if (!ev.shiftKey) { S.selected = new Set(); S.focus = null; S.windowLinks = []; draw(); }
        showPileList(under);
        return;
      }
    }
    if (hit && hit.kind === 'link' && hit.l.uid && densityMode()) { jumpTo({ uid: hit.l.uid, ts: hit.l.ts }, ev.shiftKey); return; }
    const uid = hit && (hit.kind === 'event' ? hit.e.uid : hit.kind === 'link' ? hit.l.uid : null);
    if (uid) select(uid, ev.shiftKey);
    else if (hit && hit.kind === 'cell') zoomToCell(hit, px);
    else if (zooms(hit)) zoomAtArrow(px);
  });
  canvas.addEventListener('contextmenu', (ev) => {
    const hit = hitTest(ev.offsetX, ev.offsetY);
    const uid = hit && (hit.kind === 'event' ? hit.e.uid : hit.kind === 'link' ? hit.l.uid : null);
    if (!uid) return;   // away from events and arrows, the browser's own menu opens
    ev.preventDefault();
    tip.hidden = true;
    // The pile is the clicked event and the others within the hit radius of the pointer, so the menu can name the one it
    // acts on and count the rest
    const others = hit.kind === 'event' ? eventsNear(ev.offsetX, ev.offsetY).filter((e) => e.uid !== uid) : [];
    openQuickMenu(uid, ev.clientX, ev.clientY, hit.kind === 'event' ? [hit.e, ...others] : []);
  });
}

export function eventsNear(mx, my) {
  const items = S.index[Math.floor(my / ROW_H)] || [];
  return items.filter((it) => it.kind === 'event' && Math.abs(it.x - mx) <= HIT_PX).map((it) => it.e);
}

export function showPileList(events) {
  claimDetails();   // the focused event's page, still loading after a shift-click, would replace the list
  const shown = events.slice(0, 200);
  const list = el('ul', { class: 'related badged' }, ...shown.map((e) => el('li', { onclick: (ev) => select(e.uid, ev.shiftKey) },
    markBadge(e), el('span', { class: 'pile-text' }, `${fmtUs(e.ts)}  ${e.tool}${e.hit >= 3 ? '  hit' : ''}  ${e.msg}`))));
  // The find box, kept by this pile: another pile is another list, and starts it empty
  const find = listFind(list, { page: 'pile', name: shown.map((e) => e.uid).join(','), rows: 'li', cells: '.pile-text',
                                highlight: '.pile-text', covers: 'The count still covers',
                                listed: events.length > shown.length ? shown.length : null, total: events.length, more: 'events' });
  setPage('pile', [
    el('div', { class: 'actions' },
       el('span', { class: 'muted' }, (events.length > shown.length ? `Showing the first ${shown.length}. Zoom in to separate them.`
                                                                    : 'Pick one, or zoom in to separate them.')
                                       + ' Shift-click one to add it to the selection.'), find.box),
    ...(events.length > shown.length ? [find.foot, list] : [list, find.foot])],
    { title: `${events.length.toLocaleString()} events under the cursor` });
}

export function select(uid, add) {
  if (add && S.selected.has(uid)) {
    // A shift-click that takes an event out of the selection leaves the Event page on an event no longer selected.
    // The page goes to the event selected last of those left, or to the opening hint when none is.
    S.selected.delete(uid);
    if (S.focus === uid) {
      S.focus = [...S.selected].pop() ?? null;
      S.windowLinks = [];
    }
    draw();
    if (S.focus) loadDetails(S.focus); else showHint();   // the page lists the selection, so it follows a smaller one too
    return;
  }
  if (add) S.selected.add(uid);
  else S.selected = new Set([uid]);
  if (S.focus !== uid) S.windowLinks = [];
  S.focus = uid;
  draw();
  loadDetails(uid);
}
