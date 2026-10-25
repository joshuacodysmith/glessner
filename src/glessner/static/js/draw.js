import { clockTime, pairKeys, pairLabel } from './clock.js';
import { $, cssVar, fmtGap, MARKS, OUTSIDE_GROUP, plural, ROW_H, S, STEPS_MS, windowText } from './core.js';
import { rowOfKeys, sourceRow } from './lanes.js';
import { renderWindow } from './state_line.js';
import { fmtOffset } from './zones.js';

// ---------- drawing ----------

export function sizeCanvas(canvas, w, h) {
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.round(w * dpr));
  canvas.height = Math.max(1, Math.round(h * dpr));
  canvas.style.width = `${w}px`;
  canvas.style.height = `${h}px`;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return ctx;
}

export function hexRgb(hex) {
  const n = parseInt(hex.replace('#', ''), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

export function draw() {
  const t0 = performance.now();
  const w = S.width, h = Math.max(S.rows.length * ROW_H, ROW_H);
  const ctx = sizeCanvas($('lanes'), w, h);
  const span = S.view.end - S.view.start;
  const x = (ms) => ((ms - S.view.start) / span) * w;
  const colors = {
    alt: cssVar('--row-alt'), group: cssVar('--bg'), d1: hexRgb(cssVar('--d1')), d5: hexRgb(cssVar('--d5')),
    hit: cssVar('--hit'), selected: cssVar('--select'), related: cssVar('--related'), link: cssVar('--link'),
    faded: cssVar('--muted'), pair: cssVar('--suspicious'), fg: cssVar('--fg'), panel: cssVar('--panel'),
    marks: Object.fromEntries(MARKS.map((m) => [m, cssVar(`--${m.toLowerCase()}`)])),
  };
  S.rows.forEach((row, i) => {
    if (row.children.length) { ctx.fillStyle = colors.group; ctx.fillRect(0, i * ROW_H, w, ROW_H); }
    else if (i % 2) { ctx.fillStyle = colors.alt; ctx.fillRect(0, i * ROW_H, w, ROW_H); }
  });
  S.index = S.rows.map(() => []);
  const d = S.data;
  if (d && d.mode === 'density') drawDensity(ctx, x, d, colors);
  if (d && d.mode === 'events') drawEvents(ctx, x, d, colors);
  S.linkSegs = [];
  S.linkNote = '';
  if (d && $('showLinks').checked) drawLinks(ctx, x, d.links, colors);
  drawPairLink(ctx, x, colors);
  drawAxis();
  // The Findings page's window card names the window an export covers, the one on screen, so it follows every zoom and
  // pan, and counts the events in it as the state line does.
  const exportWindow = $('exportWindow'), exportCount = $('exportWindowCount');
  if (exportWindow) exportWindow.textContent = windowText();
  if (exportCount) exportCount.textContent = S.windowPending || !d ? '…' : `${plural(d.count, 'event')} under the current Sources and View`;
  renderWindow();   // the state line's window
  return performance.now() - t0;
}

export function drawDensity(ctx, x, d, colors) {
  const n = S.groupby.length;
  const perRow = new Map();
  for (const cell of d.cells) {
    const row = rowOfKeys(cell.slice(0, n));
    if (row === undefined) continue;
    const b = cell[n], count = cell[n + 1], hit = cell[n + 2];
    const key = row * 1e7 + b;
    const acc = perRow.get(key) || { row, b, count: 0, hit: 0 };
    acc.count += count;
    acc.hit = Math.max(acc.hit, hit);
    perRow.set(key, acc);
  }
  let max = 1;
  for (const acc of perRow.values()) max = Math.max(max, acc.count);
  const logMax = Math.log(max + 1);
  for (const acc of perRow.values()) {
    const x0 = x((d.start + acc.b * d.width) / 1000), x1 = x((d.start + (acc.b + 1) * d.width) / 1000);
    const t = Math.log(acc.count + 1) / logMax;
    const rgb = colors.d1.map((c, i) => Math.round(c + (colors.d5[i] - c) * t));
    ctx.fillStyle = `rgb(${rgb.join(',')})`;
    const y = acc.row * ROW_H;
    ctx.fillRect(x0, y + 4, Math.max(1, x1 - x0 - 0.5), ROW_H - 8);
    if (acc.hit >= 3) { ctx.fillStyle = colors.hit; ctx.fillRect(x0, y + 2, Math.max(1, x1 - x0 - 0.5), 2); }
    S.index[acc.row].push({ kind: 'cell', x0, x1, count: acc.count, hit: acc.hit,
                            from: (d.start + acc.b * d.width), to: (d.start + (acc.b + 1) * d.width) });
  }
}

export function drawEvents(ctx, x, d, colors) {
  for (const e of d.events) {
    const row = rowOfKeys(e.keys);
    if (row === undefined) continue;
    const px = x(e.ts / 1000), y = row * ROW_H;
    if (e.faded) {
      // A pivot result the View hides, shown until it's marked: one flat muted tick. Opaque, so a
      // pile of them looks the same as one, where transparency would add up to full strength.
      ctx.fillStyle = colors.faded;
      ctx.fillRect(px - 1, y + 6, 2, ROW_H - 12);
      if (S.selected.has(e.uid)) { ctx.strokeStyle = colors.selected; ctx.lineWidth = 2; ctx.strokeRect(px - 4.5, y + 1, 9, ROW_H - 2); }
      S.index[row].push({ kind: 'event', x: px, e });
      continue;
    }
    if (S.related.has(e.uid)) { ctx.fillStyle = colors.related; ctx.fillRect(px - 4, y + 1, 8, ROW_H - 2); }
    if (e.mark.startsWith('Suggested: ')) {
      // A pending suggestion: hollow, in the suggested mark's color.
      const base = e.mark.slice(11);
      ctx.strokeStyle = colors.marks[base[0].toUpperCase() + base.slice(1)] || colors.marks.Unreviewed;
      ctx.lineWidth = 1;
      ctx.strokeRect(px - 1.5, y + 4.5, 3, ROW_H - 9);
    } else {
      ctx.fillStyle = colors.marks[e.mark] || colors.marks.Unreviewed;
      ctx.fillRect(px - 1.5, y + 4, 3, ROW_H - 8);
    }
    if (e.hit >= 3) { ctx.strokeStyle = colors.hit; ctx.lineWidth = 1.5; ctx.strokeRect(px - 3, y + 2.5, 6, ROW_H - 5); }
    if (S.selected.has(e.uid)) { ctx.strokeStyle = colors.selected; ctx.lineWidth = 2; ctx.strokeRect(px - 4.5, y + 1, 9, ROW_H - 2); }
    S.index[row].push({ kind: 'event', x: px, e });
  }
  for (const list of S.index) list.sort((a, b) => a.x - b.x);
  drawWindowLinks(ctx, colors);
}

// Dashed links from the focused event to events on the same host within the time window, with the gap.
export function drawWindowLinks(ctx, colors) {
  if (!S.focus || !S.windowLinks.length || S.windowLinks.length > 40) return;
  const pos = new Map();
  S.index.forEach((items, row) => items.forEach((it) => { if (it.kind === 'event') pos.set(it.e.uid, { x: it.x, y: row * ROW_H + ROW_H / 2 }); }));
  const from = pos.get(S.focus);
  if (!from) return;
  ctx.save();
  ctx.strokeStyle = colors.related;
  ctx.fillStyle = colors.related;
  ctx.setLineDash([3, 3]);
  ctx.lineWidth = 1;
  ctx.font = '10px system-ui';
  for (const w of S.windowLinks) {
    const to = pos.get(w.uid);
    if (!to) continue;
    const lift = to.y === from.y ? -8 : 0;   // same lane: arc over the row so the line is visible
    ctx.beginPath();
    ctx.moveTo(from.x, from.y);
    ctx.quadraticCurveTo((from.x + to.x) / 2, Math.min(from.y, to.y) + lift - 4, to.x, to.y);
    ctx.stroke();
    ctx.fillText(fmtGap(w.gap_s), to.x + 3, to.y - 6);
  }
  ctx.restore();
}

// A link whose ends fall in one row has nowhere to go: a host's logon to itself, or both hosts inside one folded group.
// The folded ones are counted, the window count's hover says how many, and the status line's note says
// to open the group. A link from a host with no lane, as when the Sources hide that host, has nowhere to start: those
// are counted too, and the note names the hosts.
export function drawLinks(ctx, x, links, colors) {
  const hostIdx = S.groupby.indexOf('host');
  S.linksDrawn = 0;
  S.linksFolded = 0;
  S.linksSkipped = 0;
  if (hostIdx < 0) { S.linkNote = 'Add Host to the lane keys to see logon links.'; return; }
  const laneless = new Set();
  for (const l of links.items) {
    if (!l.target_keys) continue;
    const r2 = rowOfKeys(l.target_keys);
    const r1 = l.outside ? (S.rowIndex.get('out:' + l.source) ?? S.rowIndex.get(OUTSIDE_GROUP)) : sourceRow(l.source, l.target_keys, hostIdx);
    if (r1 === undefined && r2 !== undefined && !l.outside) {
      S.linksSkipped++;
      laneless.add(l.source);
      continue;
    }
    if (r1 === undefined || r2 === undefined) continue;
    if (r1 === r2) {
      if (S.rows[r1].children.length > 0 && l.source !== l.target_keys[hostIdx]) S.linksFolded++;
      continue;
    }
    S.linksDrawn++;
    const px = x(l.ts / 1000), y1 = r1 * ROW_H + ROW_H / 2, y2 = r2 * ROW_H + ROW_H / 2;
    const count = l.count || 1;
    ctx.strokeStyle = colors.link;
    ctx.fillStyle = colors.link;
    ctx.lineWidth = links.mode === 'grouped' ? 1 + Math.min(4, Math.log2(count)) : 1.5;
    ctx.setLineDash(l.outside ? [4, 3] : []);
    ctx.beginPath(); ctx.moveTo(px, y1); ctx.lineTo(px, y2); ctx.stroke();
    ctx.setLineDash([]);
    const dir = y2 > y1 ? 1 : -1;
    ctx.beginPath(); ctx.moveTo(px, y2); ctx.lineTo(px - 4, y2 - 7 * dir); ctx.lineTo(px + 4, y2 - 7 * dir); ctx.closePath(); ctx.fill();
    if (count > 1) { ctx.font = '11px system-ui'; ctx.fillText(String(count), px + 4, (y1 + y2) / 2); }
    S.linkSegs.push({ x: px, y1: Math.min(y1, y2), y2: Math.max(y1, y2), l });
  }
  const notes = [];
  if (S.linksFolded) notes.push("Logon links inside a folded group aren't drawn; open the group to see them.");
  if (laneless.size) {
    notes.push(`Logon links from ${hostList([...laneless].sort())} aren't drawn: no lane holds ` +
               `${laneless.size === 1 ? 'its' : 'their'} events under the current Sources and View.`);
  }
  S.linkNote = notes.join(' ');
}

// Host names as a list in words, the first three named: "A", "A and B", "A, B, and C", "A, B, C, and 2 more".
function hostList(names) {
  const parts = names.length > 3 ? [...names.slice(0, 3), `${names.length - 3} more`] : names;
  return parts.length < 3 ? parts.join(' and ') : `${parts.slice(0, -1).join(', ')}, and ${parts[parts.length - 1]}`;
}

// The focused event's pair: the same moment on a host's clock and in the capture, as a
// dashed curve across lanes and time. Drawn for the selection only, since DC01 alone has 495 pairs, and kept out of
// hitTest, so it never takes a click from the ticks it crosses. When one end is outside the window, the link runs to
// that edge and ends in an arrowhead, and its label says where that end is.
export function drawPairLink(ctx, x, colors) {
  S.pairDrawn = null;
  const link = S.pairLink;
  if (!link || link.uid !== S.focus || !S.selected.has(link.uid)) return;
  const w = S.width, h = Math.max(S.rows.length * ROW_H, ROW_H);
  const a = pairEnd(link.uid, link.ts, x), b = pairEnd(link.pair.uid, link.pair.adjusted_ts_us, x);
  const inside = (p) => p.x >= 0 && p.x <= w;
  if (!a || !b || (!inside(a) && !inside(b))) return;
  let from = a, to = b, edge = null, label = pairLabel(link);
  if (!inside(a) || !inside(b)) {
    const [seen, gone, us] = inside(a) ? [a, b, link.pair.adjusted_ts_us] : [b, a, link.ts];
    edge = gone.x < 0 ? 'left' : 'right';
    from = seen;
    to = { x: edge === 'left' ? 1 : w - 1, y: gone.y };
    const seenUs = gone === b ? link.ts : link.pair.adjusted_ts_us;
    label += `; ${gone === b ? 'pair' : 'selected event'} at ${clockTime(us, seenUs)} UTC, ${edge === 'left' ? 'before' : 'after'} this window`;
  }
  // It arcs over the lanes; nearly upright, as once a clock is aligned, it bows sideways so it isn't read as a logon link.
  const upright = Math.abs(to.x - from.x) < 40 && from.y !== to.y;
  const cx = upright ? from.x + (from.x > w - 60 ? -40 : 40) : (from.x + to.x) / 2;
  const cy = upright ? (from.y + to.y) / 2 : Math.max(Math.min(from.y, to.y) - (from.y === to.y ? 16 : 10), 2);
  ctx.save();
  ctx.strokeStyle = colors.pair;
  ctx.fillStyle = colors.pair;
  ctx.lineWidth = 1.5;
  ctx.setLineDash([6, 4]);
  ctx.beginPath(); ctx.moveTo(from.x, from.y); ctx.quadraticCurveTo(cx, cy, to.x, to.y); ctx.stroke();
  ctx.setLineDash([]);
  if (edge) {   // an arrowhead along the curve's last stretch
    const angle = Math.atan2(to.y - cy, to.x - cx);
    ctx.beginPath(); ctx.moveTo(to.x, to.y);
    ctx.lineTo(to.x - 8 * Math.cos(angle - 0.45), to.y - 8 * Math.sin(angle - 0.45));
    ctx.lineTo(to.x - 8 * Math.cos(angle + 0.45), to.y - 8 * Math.sin(angle + 0.45));
    ctx.closePath(); ctx.fill();
  } else {   // a ring around the pair
    ctx.beginPath(); ctx.arc(to.x, to.y, 6, 0, 2 * Math.PI); ctx.stroke();
  }
  // The label sits above the curve's middle, beside it when upright, or by the arrowhead, on a panel-colored box so it
  // reads over density bars.
  ctx.font = '11px system-ui';
  const bw = ctx.measureText(label).width + 8, bh = 15;
  const mx = (from.x + 2 * cx + to.x) / 4, my = (from.y + 2 * cy + to.y) / 4;   // the curve's middle
  const lx = edge === 'left' ? 4 : edge === 'right' ? w - bw - 4 : !upright ? mx - bw / 2 : cx > from.x ? mx + 6 : mx - bw - 6;
  const ly = edge ? to.y - bh - 8 : upright ? my - bh / 2 : my - bh - 3;
  const bx = Math.min(Math.max(lx, 2), Math.max(w - bw - 2, 2)), by = Math.min(Math.max(ly, 2), Math.max(h - bh - 2, 2));
  ctx.fillStyle = colors.panel;
  ctx.fillRect(bx, by, bw, bh);
  ctx.lineWidth = 1;
  ctx.strokeRect(bx + 0.5, by + 0.5, bw - 1, bh - 1);
  ctx.fillStyle = colors.fg;
  ctx.fillText(label, bx + 4, by + 11);
  ctx.restore();
  S.pairDrawn = { from: link.uid, to: link.pair.uid, rows: [a.row, b.row], edge, label };   // rows: for the tests
}

// Where an end of the pair link is: its drawn tick, or its lane and time when it isn't drawn as one.
function pairEnd(uid, ts, x) {
  for (const [row, items] of S.index.entries()) {
    for (const it of items) if (it.kind === 'event' && it.e.uid === uid) return { x: it.x, y: row * ROW_H + ROW_H / 2, row };
  }
  const keys = pairKeys(uid);
  const row = keys ? rowOfKeys(keys) : undefined;
  return row === undefined ? null : { x: x(ts / 1000), y: row * ROW_H + ROW_H / 2, row };
}

export function drawAxis() {
  const w = S.width;
  const span = S.view.end - S.view.start;
  const step = STEPS_MS.find((s) => (s / span) * w >= 110) || STEPS_MS[STEPS_MS.length - 1];
  const ticks = [];
  // A case without events on the timeline has no times to label; its axis would read 2 s around 1970-01-01 00:00:00.
  if (S.meta?.rows) for (let t = Math.ceil(S.view.start / step) * step; t <= S.view.end; t += step) ticks.push(t);
  const x = (t) => ((t - S.view.start) / span) * w;
  const muted = cssVar('--muted'), line = cssVar('--line');
  const ctx = sizeCanvas($('axis'), w, 30);
  ctx.fillStyle = muted;
  ctx.strokeStyle = line;
  ctx.font = '11px system-ui';
  for (const t of ticks) {
    ctx.beginPath(); ctx.moveTo(x(t), 22); ctx.lineTo(x(t), 30); ctx.stroke();
    const iso = new Date(t).toISOString();
    const label = step >= 864e5 ? iso.slice(0, 10) : step >= 6e4 ? iso.slice(5, 16).replace('T', ' ') : iso.slice(11, 19);
    ctx.fillText(label, x(t) + 3, 16);
  }
  // Zone axes label the same instants in their own local time, so a tick reads straight
  // down from UTC to each zone. Local times rarely fall on midnight, so day-scale ticks show the hour too.
  for (const z of S.zoneAxes) {
    const zc = sizeCanvas(z.canvas, w, 20);
    zc.fillStyle = muted;
    zc.strokeStyle = line;
    zc.font = '11px system-ui';
    for (const t of ticks) {
      const p = z.clock.parts(t);
      zc.beginPath(); zc.moveTo(x(t), 0); zc.lineTo(x(t), 5); zc.stroke();
      zc.fillText(step >= 6e4 ? `${p.mo}-${p.d} ${p.h}:${p.mi}` : `${p.h}:${p.mi}:${p.s}`, x(t) + 3, 15);
    }
    const a = z.clock.parts(S.view.start), b = z.clock.parts(S.view.end);
    z.offsetEl.textContent = a.offset === b.offset ? `${a.abbr}, UTC${fmtOffset(a.offset)}`
      : `${a.abbr} to ${b.abbr}, UTC${fmtOffset(a.offset)} to ${fmtOffset(b.offset)}`;
  }
}
