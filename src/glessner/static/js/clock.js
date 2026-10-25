import { $, api, el, fmtMs, plural, post, S, setStatus } from './core.js';
import { animateView, cancelAnimation } from './data.js';
import { draw } from './draw.js';
import { button, focusedPageAction, loadDetails } from './event_page.js';
import { filterParam } from './filters.js';
import { applyHosts, hostInfo } from './hosts.js';
import { renderStateLine } from './state_line.js';

// ---------- host clocks against the capture ----------
// The server pairs host events with the capture's records of the same moments and measures how far each host's clock
// ran from the capture's (clock.py). Times stay as recorded until the analyst aligns them. Aligning sets an ordinary
// journaled clock offset, which changes what the page shows and never the evidence times.

const MEASURED = ['suggest', 'agrees'];   // the states with a skew the pairs agree on
const direction = (c) => (c.skew_seconds < 0 ? 'behind' : 'ahead of');
const signedSkew = (c) => `${c.skew_seconds < 0 ? '-' : '+'}${c.skew_text}`;
const fmtSeconds = (s) => `${s > 0 ? '+' : ''}${s.toLocaleString()} s`;
const offsetOf = (host) => (hostInfo(host) || {}).offset_seconds || 0;
const clockDetails = (c) => [`Measured against ${c.reference}, ${c.basis_text}.`, c.zone_note, c.steps_text, c.span_note,
                             c.sensors_note].filter(Boolean).join('\n');

// A time to the millisecond, with its date when that isn't the date of `refUs`.
export function clockTime(us, refUs) {
  const text = fmtMs(Math.round(us / 1000));
  return refUs != null && text.slice(0, 10) === fmtMs(Math.round(refUs / 1000)).slice(0, 10) ? text.slice(11) : text;
}

// The Case panel's switch: which half holds, "partly aligned" when some measured hosts are aligned and some aren't, or
// neither half, when no host is aligned but one has an offset that isn't its suggestion (clock.alignment).
export function renderClockSwitch() {
  const state = S.meta.clock_alignment || 'none';
  $('clockSwitch').hidden = state === 'none';
  $('clockSwitch').dataset.state = state;
  $('clockRecorded').setAttribute('aria-pressed', String(state === 'recorded'));
  $('clockAligned').setAttribute('aria-pressed', String(state === 'aligned'));
  $('clockPartly').hidden = state !== 'partly';
  renderStateLine();   // its clock part
}

// One alignment at a time. A second click before the first one's answer would read the same offsets, so its post
// would journal each change again and the Event page's event would move twice. The switch's halves
// and the Align buttons say they're busy with aria-disabled, which, unlike disabled, keeps the keyboard focus on them.
let aligning = false;
function setAligning(on) {
  aligning = on;
  for (const b of document.querySelectorAll('#clockSwitch button, button.align-clock')) {
    if (on) b.setAttribute('aria-disabled', 'true'); else b.removeAttribute('aria-disabled');
  }
}

// After a re-render took away the button that had the focus, focus `target()`, unless the focus has moved on since.
// The Hosts panel's split controls use it too.
export function refocus(target) {
  if (document.activeElement && document.activeElement !== document.body) return;
  const node = target && target();
  if (node) node.focus();
}

// Align to the capture ('capture') or go back to the times as recorded ('recorded'), for every measured host or one.
// `target` gives the control to focus once the page is drawn again, for an action whose button the re-render removes.
export async function alignClocks(to, host = null, target = null) {
  if (aligning) return;
  if (to === 'recorded' && !S.meta.hosts.some((h) => h.offset_aligned && (!host || h.host === host))) {
    const typed = S.meta.hosts.filter((h) => h.offset_seconds).map((h) => h.host);
    setStatus(typed.length ? `There are no offsets from this switch to set back. Offsets typed in the Hosts panel stay: ${typed.join(', ')}.`
      : 'The measured clocks agree with the capture as recorded, so there is no offset to set back.');
    return;
  }
  const keep = S.focusEvent && S.focusEvent.uid === S.focus && S.focusEvent.recorded != null ? S.focusEvent : null;
  const was = keep ? offsetOf(keep.host) : 0;
  const at = keep ? keep.recorded / 1000 + was * 1000 : null;   // where it's drawn now, in ms
  const done = focusedPageAction();
  setAligning(true);
  try {
    let res;
    try { res = await post('/api/host', host ? { align: to, host } : { align: to }); }
    catch (err) { setStatus(`Clock alignment failed: ${err.message}`); return; }
    // The Event page's event stays where it is on screen, so its pair in the capture comes to meet it. The shift is
    // this post's own, from its answer.
    const now = keep ? (res.hosts.find((h) => h.host === keep.host) || {}).offset_seconds || 0 : 0;
    const shift = (now - was) * 1000;
    if (shift && at >= S.view.start && at <= S.view.end) {
      cancelAnimation();
      S.view = { start: S.view.start + shift, end: S.view.end + shift };
    }
    await applyHosts(res, done, { moved: true });   // the case's range moves with the offsets, and Fit case with it
    refocus(target);
  } finally { setAligning(false); }
}

// The skew in a readable unit for a lane flag: +1 h for 3,599.5 s, +12 min, +42 s, +0.6 s. The exact figure is in
// the hover text, the Hosts panel, and the Event page.
function roughSkew(c) {
  const s = Math.abs(c.skew_seconds), sign = c.skew_seconds < 0 ? '-' : '+';
  const [value, unit] = s >= 3600 * 0.95 ? [s / 3600, 'h'] : s >= 60 ? [s / 60, 'min'] : [s, 's'];
  const shown = value >= 10 || unit === 'min' ? String(Math.round(value)) : String(Math.round(value * 10) / 10);
  return `${sign}${shown} ${unit}`;
}

// A host lane label's flag: how far its clock ran from the capture's, or, once its offset agrees, a muted "aligned to
// the capture", with an asterisk when the host logged clock changes. Short, because lane labels are narrow: at the
// default width a longer wording such as "clock +59m59.5s vs capture, changed twice" is cut off. The flag reads
// "clock +1 h", and a clock change is the asterisk, since a second flag leaves no room on a label of that width. The
// hover text explains the asterisk first, then says how the clock was measured.
export function clockBadges(row) {
  if (row.key !== 'host') return [];
  const h = hostInfo(row.label), c = h && h.clock;
  if (!c || !MEASURED.includes(c.state)) return [];
  const n = c.steps.length;
  const changed = n ? `* ${h.host}'s clock was changed ${n === 1 ? 'once' : n === 2 ? 'twice' : `${n} times`}; when, and the span one offset fits, are below.\n` : '';
  const why = `${changed}${h.host}'s clock ran ${c.skew_text} ${direction(c)} the capture.\n${clockDetails(c)}`;
  const mark = n ? '*' : '';
  return [c.state === 'agrees'
    ? el('span', { class: 'clock-flag aligned', 'data-clock': c.state, title: `${c.reason}\n${why}` }, `aligned to the capture${mark}`)
    : el('span', { class: 'clock-flag', 'data-clock': c.state, title: why }, `clock ${roughSkew(c)}${mark}`)];
}

// The Hosts panel's Clock offset cell, under the number: what the check found, and Align to the capture when it
// suggests an offset.
export function clockCell(h) {
  const c = h.clock;
  if (!c || !c.state) return [];
  if (c.state === 'suggest') {
    const notes = [c.zone_note, h.offset_seconds ? `Its offset of ${fmtSeconds(h.offset_seconds)} doesn't match the suggested ${c.display}.` : '',
                   c.steps_text, c.span_note, c.sensors_note].filter(Boolean);
    return [el('div', { class: 'clock-check flag', 'data-clock': c.state },
      el('div', { class: 'clock-head' }, `Clock looks ${c.skew_text} ${direction(c)} the capture`),
      el('div', {}, `Measured against ${c.reference}, ${c.basis_text}.`),
      ...notes.map((text) => el('div', { class: 'muted' }, text)),
      // Once aligned, the button goes, and the focus goes to the offset it set.
      button('Align to the capture', () => alignClocks('capture', h.host, () => hostOffsetInput(h.host)),
             { class: 'align-clock', 'aria-label': `Align to the capture: ${h.host}`,
               title: `Set the offset to ${c.display}, journaled. Evidence times don't change.` }))];
  }
  if (c.state === 'agrees') {
    return [el('div', { class: 'clock-check muted', 'data-clock': c.state, title: `${c.reason}\n${clockDetails(c)}` }, 'Aligned to the capture')];
  }
  if (c.state === 'disagree') {
    const groups = c.clusters.map((g) => `${fmtSeconds(g.seconds)} (${plural(g.pairs, 'pair')})`).join(', ');
    return [el('div', { class: 'clock-check disagree', 'data-clock': c.state },
      el('div', { class: 'clock-head' }, 'Pairs with the capture disagree'),
      ...(groups ? [el('div', {}, `Groups of pairs suggest ${groups}.`)] : []),
      el('div', { class: 'muted' }, c.reason))];
  }
  return c.reason ? [el('div', { class: 'clock-check muted', 'data-clock': c.state }, c.reason)] : [];
}

// How far the host's clock ran from the capture's and which times the page shows.
function clockSentence(ev) {
  const c = ev.clock;
  const text = `${c.host}'s clock ran ${c.skew_text} ${direction(c)} the capture ` +
               `(${c.inliers.toLocaleString()} of ${c.pairs.toLocaleString()} pairs agree).`;
  // A capture record's own time is the capture's, so for one the sentence is about its pair's host on the timeline.
  const whose = ev.host === c.host ? 'Times here' : `${c.host}'s times on the timeline`;
  const offset = ev.host === c.host ? ev.offset_us / 1e6 : offsetOf(c.host);
  return text + (c.state === 'agrees' ? ` ${whose} are aligned to the capture.`
    : offset ? ` ${whose} include its ${fmtSeconds(offset)} offset, not the ${c.display} that aligns them.`
    : ` ${whose} are as recorded.`);
}

// An event on an aligned host with no pair of its own has nothing to act on, and on a case aligned to its capture that is
// nearly every event. Its note then goes into the hover of the header's chip instead of a third row, or of the
// time when the host's clock was right and needs no offset, so there is no chip. A pair, a suggestion,
// and a disagreement keep the note, since each asks for a look or a click.
export const clockFolds = (ev) =>
  !!(ev.clock && ev.clock.state === 'agrees' && !ev.pair && ev.host === ev.clock.host);
export const clockHover = (ev) => `${clockSentence(ev)}\n${clockDetails(ev.clock)}`;

// The Event page's note under the event's time, when its host's measured offset fits it: how far the clock ran, which
// times the page shows, and the event's pair in the capture or on its host.
export function clockNote(ev) {
  const c = ev.clock, p = ev.pair;
  if (!c) return [];
  const lines = [el('div', {}, clockSentence(ev))];
  if (p) {
    lines.push(el('div', {}, p.in_capture
      ? `This event's pair: ${p.message}, seen in the capture at ${clockTime(p.adjusted_ts_us, ev.adjusted_ts_us)} UTC.`
      : `This record's pair on ${p.host}: ${p.message}, recorded at ${clockTime(p.ts_us, ev.adjusted_ts_us)} on ${p.host}'s clock.`));
  }
  const actions = [
    ...(p ? [button('Show the pair', () => showPair(ev), { class: 'linklike', title: `Select the pair and fit both in the window. Both record the same ${p.kind}.` })] : []),
    ...(c.state === 'suggest' ? [button(`Align ${c.host} to the capture`, () => alignClocks('capture', c.host, eventClockControl),
                                        { class: 'align-clock',
                                          title: `Set ${c.host}'s clock offset to ${c.display}, journaled. Evidence times don't change.` })] : []),
  ];
  if (actions.length) lines.push(el('div', { class: 'ev-clock-actions' }, ...actions));
  // tabindex -1: the focus can come back to the note when the re-render removed the button that had it
  return [el('div', { class: `ev-clock ${c.state}`, title: clockDetails(c), tabindex: '-1' }, ...lines)];
}

// The controls that take the focus back after a re-render: a host's offset in the Hosts panel, and the Event page's
// first clock button (Show the pair), or else its clock note, or the header's chip that holds the note once aligning
// folded it.
const hostOffsetInput = (host) => $('hostsTable').querySelector(`tr[data-host="${CSS.escape(host)}"] input[type=number]`);
const eventClockControl = () => $('details').querySelector('.ev-clock button') || $('details').querySelector('.ev-clock')
  || $('details').querySelector('.ev-ident [data-clock]');

// ---------- the link from the focused event to its pair, drawn by draw.js's drawPairLink ----------

// The timeline's lanes and filter: an end's lane keys hold while these do, and while its mark and host's role do.
const laneSpec = () => `groupby=${S.groupby.join(',')}${filterParam()}`;

// Called by the Event page with each event it loads. The keys are looked up only when an end needs them (pairKeys), so
// a link whose ends are both ticks costs no request. A re-render of the same link, after a mark or a
// host edit, may have moved an end to another lane, so its keys are looked up again; the old ones are drawn meanwhile,
// so the link doesn't blink.
export function setPairLink(uid, ev) {
  const was = S.pairLink;
  if (!ev.pair) {
    S.pairLink = null;
    if (was) draw();
    return;
  }
  const same = was && was.uid === uid && was.pair.uid === ev.pair.uid;
  S.pairLink = { uid, ts: ev.adjusted_ts_us, pair: ev.pair, clock: ev.clock, keys: same ? was.keys : {},
                 lanes: null, asked: null, held: same ? was.lanes || was.held : null };
  draw();
}

// Each end's lane keys, for drawing an end that isn't a tick on the canvas: one outside the window, or either when
// zoomed out to density bars. /api/event_keys gets them by ID, with the timeline's own lanes and filter, so an end the
// filter hides gets no lane. Looked up by time, a microsecond more than 100 events share came back as density cells,
// with no lane for the end.
async function findLanes(link) {
  const spec = laneSpec();
  link.asked = spec;
  const uids = [link.uid, link.pair.uid];
  const d = await api(`/api/event_keys?uids=${uids.map(encodeURIComponent).join(',')}&${spec}`).catch(() => ({}));
  if (S.pairLink !== link || link.asked !== spec) return;   // another event, or other lanes, since
  link.keys = Object.fromEntries(uids.map((uid) => [uid, (d.keys || {})[uid] || null]));
  link.lanes = spec;
  draw();
}

// An end's lane keys while they hold, or the ones a re-render kept while they're looked up again; when the lanes or
// filter changed, there are none until the lookup ends.
export function pairKeys(uid) {
  const link = S.pairLink;
  if (!link) return null;
  const spec = laneSpec();
  if (link.lanes !== spec && link.asked !== spec) findLanes(link);
  return link.lanes === spec || link.held === spec ? link.keys[uid] || null : null;
}

// The link's label: what the pair recorded, and the host clock's skew.
export function pairLabel(link) {
  const c = link.clock;
  return `same ${link.pair.kind}` + (c ? `, host clock ${signedSkew(c)}` : '') +
         (c && c.state === 'agrees' && offsetOf(c.host) ? ', aligned' : '');
}

// Show the pair: select it and fit both in the window with a margin; its Event page then links back to this event,
// and its Show the pair takes the focus the old page's button had.
export async function showPair(ev) {
  const p = ev.pair;
  const a = ev.adjusted_ts_us / 1000, b = p.adjusted_ts_us / 1000;
  const margin = Math.max(Math.abs(a - b) * 0.15, 15000);
  S.selected = new Set([p.uid]);
  if (S.focus !== p.uid) S.windowLinks = [];
  S.focus = p.uid;
  loadDetails(p.uid, p.adjusted_ts_us).then(() => { if (S.focus === p.uid) refocus(eventClockControl); });
  await animateView(Math.min(a, b) - margin, Math.max(a, b) + margin);
}
