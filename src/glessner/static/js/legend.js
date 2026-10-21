// The legend: every mark the timeline draws today, as draw.js draws it, in the same color tokens, so it
// reads right in dark mode too. It adds nothing to the timeline. The Legend button and the L key show or hide it, and
// this browser remembers which.

import { $, el, panelBand, S, setPanelButton } from './core.js';
import { scheduleFetch } from './data.js';
import { resize } from './main.js';

const LEGEND_KEY = 'glessner.legendOpen';   // per-viewer preference
const SVG = 'http://www.w3.org/2000/svg';

function legendStored() {
  try { return localStorage.getItem(LEGEND_KEY) === 'open'; } catch (_) { return false; }
}

export function setupLegend() {
  $('legendButton').addEventListener('click', () => setLegend($('legendPanel').hidden));
  // L shows or hides it from anywhere on the timeline, except while typing in a field or with a modifier key
  document.addEventListener('keydown', (ev) => {
    if (ev.key !== 'l' && ev.key !== 'L') return;
    if (ev.ctrlKey || ev.metaKey || ev.altKey || ev.repeat) return;
    if (ev.target.closest && ev.target.closest('input, textarea, select, [contenteditable]')) return;
    if (!$('overview').hidden) return;   // the legend is the timeline's
    ev.preventDefault();
    setLegend($('legendPanel').hidden);
  });
  setLegend(legendStored(), { save: false, relayout: false });   // the page lays the timeline out once it has lanes
}

export function setLegend(open, { save = true, relayout = true } = {}) {
  const panel = $('legendPanel');
  if (open) panel.replaceChildren(...legend());   // drawn when opened: it names the case's event threshold
  panel.hidden = !open;
  setPanelButton('legendButton', open);
  if (save) {
    try { localStorage.setItem(LEGEND_KEY, open ? 'open' : 'closed'); } catch (_) { /* kept for this page only */ }
  }
  if (!relayout) return;
  resize();          // the Timeline panel just changed width
  scheduleFetch();
}

// A 34 by 20 swatch, the size of one lane row around a tick at x = 17, as draw.js places them (ROW_H is 20).
function swatch(...shapes) {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 34 20');
  svg.setAttribute('aria-hidden', 'true');
  for (const [tag, attrs, text] of shapes) {
    const node = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (text) node.textContent = text;
    svg.append(node);
  }
  return svg;
}

// draw.js's shapes, at a tick drawn at px = 17 in a row from y = 0 to 20
const tick = (cls) => ['rect', { x: 15.5, y: 4, width: 3, height: 12, class: cls }];
const item = (picture, ...text) => el('div', { class: 'lg-item' }, picture, el('div', {}, ...text));
const flagItem = (flag, text) => el('div', { class: 'lg-item flagrow' }, flag, el('div', {}, text));
const head = (cls, d) => ['path', { d, class: cls }];

function legend() {
  const threshold = (S.meta && S.meta.event_threshold || 50000).toLocaleString();
  const seconds = S.meta ? S.meta.time_window_seconds : 60;
  return [
    panelBand('Legend'),
    el('div', { class: 'muted' }, 'What each mark on the timeline means. Toggle with the Legend button or L.'),
    el('h3', {}, 'Event ticks, by your mark'),
    ...['Unreviewed', 'Authorized', 'Suspicious', 'Malicious'].map((m) => item(swatch(tick(`lg-${m.toLowerCase()}`)), m)),
    item(swatch(['rect', { x: 15.5, y: 4.5, width: 3, height: 11, class: 'lg-hollow' }]),
         "Hollow: a suggestion waiting for Accept or Reject, in the suggested mark's color"),
    el('h3', {}, 'Boxes and fills'),
    item(swatch(tick('lg-unreviewed'), ['rect', { x: 14, y: 2.5, width: 6, height: 15, class: 'lg-hit' }]),
         'Red box: the event has a Hayabusa hit at medium, high, or critical level'),
    item(swatch(tick('lg-unreviewed'), ['rect', { x: 12.5, y: 1, width: 9, height: 18, class: 'lg-select' }]),
         'Heavy box: selected; the next mark applies to every selected event'),
    item(swatch(['rect', { x: 13, y: 1, width: 8, height: 18, class: 'lg-related' }], tick('lg-unreviewed')),
         "Yellow behind a tick: the last pivot's results, a search's matches, or the events a Suggestions page lists"),
    item(swatch(['rect', { x: 16, y: 6, width: 2, height: 8, class: 'lg-faded' }]),
         'Thin gray tick: a pivot result the View hides, drawn faded until it is marked or the next pivot replaces it'),
    el('h3', {}, 'Zoomed out'),
    item(swatch(['rect', { x: 1, y: 4, width: 9, height: 12, class: 'lg-d1' }], ['rect', { x: 12, y: 4, width: 9, height: 12, class: 'lg-d3' }],
                ['rect', { x: 23, y: 4, width: 9, height: 12, class: 'lg-d5' }]),
         `Shaded bar: how many events fall in that stretch of the lane, light to dark on a log scale. Drawn while the window holds more than ${threshold} events.`),
    item(swatch(['rect', { x: 12, y: 4, width: 9, height: 12, class: 'lg-d3' }], ['rect', { x: 12, y: 2, width: 9, height: 2, class: 'lg-hitline' }]),
         'Red top edge: the stretch holds an event with a Hayabusa hit at medium level or above'),
    el('h3', {}, 'Lines'),
    item(swatch(['line', { x1: 17, y1: 19, x2: 17, y2: 1, class: 'lg-link' }], head('lg-link-head', 'M17 1 L13 8 L21 8 Z')),
         "Arrow: a logon, from its source host's lane to the host that recorded it"),
    item(swatch(['line', { x1: 17, y1: 19, x2: 17, y2: 1, class: 'lg-link outside' }], head('lg-link-head', 'M17 1 L13 8 L21 8 Z')),
         'Dashed arrow: a logon from a source outside the case'),
    item(swatch(['line', { x1: 13, y1: 19, x2: 13, y2: 1, class: 'lg-link grouped' }], head('lg-link-head', 'M13 1 L9 8 L17 8 Z'),
                ['text', { x: 19, y: 13, class: 'lg-link-count' }, '12']),
         'Thick arrow with a number: logons grouped, when the window has more than 300 links'),
    item(swatch(['path', { d: 'M3 14 Q 17 2 31 14', class: 'lg-window' }], ['text', { x: 22, y: 9, class: 'lg-window-gap' }, '+4s']),
         `Dashed yellow line with a gap such as +4s: an event on the selected event's host within the time window (±${seconds} s), after that pivot, when there are 40 or fewer`),
    item(swatch(['path', { d: 'M3 17 Q 17 0 29 12', class: 'lg-pair' }], ['circle', { cx: 29, cy: 12, r: 4, class: 'lg-pair' }]),
         "Dashed amber line: the same moment on the selected event's host clock and in the capture, ringed at the pair, or with an arrow at the window's edge when the pair is outside it"),
    el('h3', {}, 'Lane labels'),
    flagItem(el('span', { class: 'lg-flag clock-flag' }, 'clock +1 h'),
             "The host's clock ran that far from the capture's; an asterisk means the host logged clock changes"),
    flagItem(el('span', { class: 'lg-flag clock-flag aligned' }, 'aligned to the capture'),
             "The host's offset aligns it to the capture"),
    flagItem(el('span', { class: 'lg-flag guess' }, 'guessed'),
             "The host's role is a guess not yet confirmed; on a role label, how many of its hosts"),
  ];
}
