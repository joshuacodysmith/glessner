// The state line under the Timeline's toolbar, always in view: how many of the case's events the
// timeline shows, each hidden category with a Show that clears that one alone, which clock the times are on, and the
// window. A hidden filter is how a wrong conclusion starts. It's drawn again after each change that affects it: the
// lanes' counts after a filter, a mark, or a host edit (lanes.js), the machine-account switch, the clocks (clock.js),
// and the window on every draw (draw.js).

import { alignClocks } from './clock.js';
import { $, api, el, fmtMs, plural, S } from './core.js';
import { fetchView } from './data.js';
import { button } from './event_page.js';
import { clearFilters, describePred, filterParam } from './filters.js';
import { describeValue, usePreset } from './view.js';

// The Sources hide something only with an only or a hide pred; a show pred alone is an exception to no hide, as the
// server reads them (server.sources_part)
export const sourcesOn = () => S.filter.only.length + S.filter.hide.length > 0;

export function renderStateLine() {
  if (!S.meta) return;
  renderShown();
  renderHidden();
  renderClock();
  renderWindow();
}

// The counts the lanes can't give: with lanes by tactic, the events shown, since an event with two tactics sits in two
// lanes; and with both the Sources and a View on, what each part alone shows. Asked after the lanes answer, so no
// redraw waits on the scan (server.api_shown_counts). An answer for an earlier filter or grouping is dropped.
let countTurn = 0;
let counting = Promise.resolve();
export function countShown() {
  const turn = ++countTurn;
  S.sourcesShown = null;
  S.viewShown = null;
  if (S.lanesShown != null && !(sourcesOn() && S.viewSpec)) { counting = Promise.resolve(); return counting; }
  counting = api(`/api/shown_counts?groupby=${S.groupby.join(',')}${filterParam()}`).then((res) => {
    if (turn !== countTurn) return;
    S.lanesShown = res.shown;
    S.sourcesShown = res.sources_shown ?? null;
    S.viewShown = res.view_shown ?? null;
    renderStateLine();
  }).catch(() => { /* the line keeps saying "..." */ });
  return counting;
}

// Once the counts for the current filter are in, as a View the overview opens waits for them
export const shownCounted = () => counting;

// "Showing X of Y events on the timeline", the one total: Y is the case's events on the timeline, those with a time,
// Hayabusa's hits aside; X is those the Sources and View show, over the whole case, faded pivot results among them, from the
// lanes' own count. Hide machine accounts takes links away, not events, so it changes neither. The window's own count
// follows it (renderWindow), so the two numbers can't be read as rival totals.
function renderShown() {
  const total = S.meta.rows || 0, shown = S.lanesShown;
  $('stShown').replaceChildren('Showing ', el('b', {}, shown == null ? '...' : shown.toLocaleString()), ' of ',
                               el('b', {}, total.toLocaleString()), ' events on the timeline');
  $('stShown').title = 'Events the timeline can draw under the current Sources and View, at any time in the case, of ' +
    "the case's events that have a time. Hayabusa's hits mark their events and aren't counted. Pivot results the View " +
    'shows faded count as shown.';
}

// A pill names what it hides when that's one thing, and counts the choices otherwise; the hover lists them all.
function named(list) {
  if (!list.length) return '';
  return list.length === 1 ? ` (${list[0]})` : ` (${list.length} choices)`;
}

// One pill per hidden category. With both a Sources choice and a View on, each counts its own: the Sources hide what
// the case holds beyond what they show, and the View hides what the Sources show beyond what the timeline shows.
function renderHidden() {
  const total = S.meta.rows || 0, shown = S.lanesShown;
  const sources = sourcesOn(), view = !!S.viewSpec;
  const known = shown != null && (!(sources && view) || S.sourcesShown != null);
  const pills = [];
  if (sources) {
    const n = !known ? null : view ? total - S.sourcesShown : total - shown;
    const rules = [...S.filter.only.map((p) => `only ${describePred(p)}`), ...S.filter.hide.map((p) => `hiding ${describePred(p)}`)];
    const kept = S.filter.show.map((p) => `showing ${describePred(p)}`);
    pills.push(pill(`Hidden by Sources${named(rules.map((r) => r.replace(/^hiding /, '')))}: ${n == null ? '...' : plural(n, 'event')}`,
                    'Show', () => clearFilters(),
                    { id: 'stHiddenSources', title: `Sources: ${[...rules, ...kept].join('; ')}. Show clears the Sources and keeps the View.` }));
  }
  if (view) {
    const n = !known ? null : sources ? S.sourcesShown - shown : total - shown;
    const what = [...S.viewSpec.marks, ...S.viewSpec.values.map(describeValue)];
    pills.push(pill(`Hidden by the View${what.length === 1 ? ` (only ${what[0]})` : ` (${what.length} choices)`}: ` +
                    `${n == null ? '...' : plural(n, 'event')}`, 'Show', () => usePreset(null),
                    { id: 'stHiddenView', title: `View: only ${what.join(', ')}. Show turns the View off and keeps the Sources.` }));
  }
  if ($('hideMachine').checked) {
    const n = S.machineLinks;
    pills.push(pill(`Hidden: machine-account logon links${n == null ? '' : ` (${n.toLocaleString()})`}`, 'Show',
                    () => { $('hideMachine').checked = false; machineChanged(); },
                    { id: 'stHiddenMachine', title: 'Logon links by accounts ending in $, mostly routine, are left off the ' +
                      'timeline; the number counts them over the whole case. Their events stay.' }));
  }
  $('stHidden').replaceChildren(...pills);
}

export function machineChanged() {
  fetchView();
  renderStateLine();
}

const pill = (text, label, action, { id, title, flag = false }) => el('span', { class: flag ? 'pill flag' : 'pill', id, title },
  el('span', {}, text), button(label, action));

// Which clock the times are on: as recorded, aligned to the capture, partly, or with offsets
// that aren't the capture's, with Align or Show recorded where the switch would change something. The pill is short,
// so the lanes keep their height; its hover says it in full.
function renderClock() {
  const state = S.meta.clock_alignment || 'none', hosts = S.meta.hosts || [];
  const skew = (h) => `${h.host} ${h.clock.skew_seconds < 0 ? '-' : '+'}${h.clock.skew_text}`;
  const offset = (h) => `${h.host} ${h.offset_seconds > 0 ? '+' : ''}${h.offset_seconds.toLocaleString()} s`;
  const suggest = hosts.filter((h) => h.clock && h.clock.state === 'suggest');
  const aligned = hosts.filter((h) => h.offset_aligned);
  const typed = hosts.filter((h) => h.offset_seconds && !h.offset_aligned);
  const align = button('Align', () => alignClocks('capture'), { id: 'stAlign', title: "Set each measured host's suggested offset, journaled" });
  const recorded = button('Show recorded', () => alignClocks('recorded'), { id: 'stRecorded', title: 'Set back the offsets the Times switch set' });
  let text, long, buttons = [], flag = false;
  if (state === 'recorded') {
    text = `Recorded times: ${suggest.map(skew).join(', ')} vs capture`;
    long = `Times as each host's clock recorded them. Measured against the capture: ${suggest.map(skew).join(', ')}.`;
    buttons = [align];
    flag = true;
  } else if (state === 'aligned' && aligned.length) {
    text = `Aligned to capture: ${aligned.map(offset).join(', ')}`;
    long = `Times aligned to the capture by these offsets: ${aligned.map(offset).join(', ')}. Evidence times never change.`;
    buttons = [recorded];
  } else if (state === 'aligned') {
    text = 'Times: UTC, clocks agree with capture';
    long = 'Times in UTC. The measured clocks agree with the capture as recorded.';
  } else if (state === 'partly') {
    text = `Partly aligned: ${aligned.map(offset).join(', ')}; recorded: ${suggest.map(skew).join(', ')}`;
    long = `Times partly aligned to the capture: ${aligned.map(offset).join(', ')} aligned, and ${suggest.map(skew).join(', ')} ` +
           'as each clock recorded them.';
    buttons = [align, recorded];
    flag = true;
  } else if (state === 'neither') {
    text = `Offsets not from capture: ${typed.map(offset).join(', ')}`;
    long = `Times with clock offsets that aren't the capture's: ${typed.map(offset).join(', ')}.`;
    buttons = [align];
    flag = true;
  } else {
    text = typed.length ? 'Times: UTC' : 'Times: UTC, as recorded';
    long = typed.length ? 'Times in UTC.' : 'Times in UTC, as each host recorded them. No clock was measured against a capture.';
  }
  if (typed.length && state !== 'neither') {
    text += `; offsets: ${typed.map(offset).join(', ')}`;
    long += ` Clock offsets set in the Hosts panel: ${typed.map(offset).join(', ')}.`;
  }
  $('stClock').replaceChildren(el('span', { class: flag ? 'pill flag' : 'pill', id: 'stClockPill', title: long },
                                  el('span', {}, text), ...buttons));
}

// The window, start to end in UTC to the millisecond, as the Findings page's window card names it, and its span; and, after the total, how
// many events lie in it ("In this window"). That count is the window's data: it reads "…" from the moment the window changes
// until the data for the new one answers, and its hover says what it counts and how many logon links are drawn.
export function renderWindow() {
  const box = $('stWindow'), count = $('stInWindow');
  // Nothing before the first window is set, nor on a case without events on the timeline
  if (!box || !S.meta || !S.meta.rows || (S.view.start === 0 && S.view.end === 1)) {
    if (box) box.replaceChildren();
    if (count) { count.replaceChildren(); count.title = ''; }
    return;
  }
  const a = fmtMs(S.view.start), b = fmtMs(S.view.end);
  const end = a.slice(0, 10) === b.slice(0, 10) ? b.slice(11) : b;
  box.replaceChildren('Window ', el('b', {}, `${a} to ${end} UTC`), `, ${spanText(S.view.end - S.view.start)}`);
  if (!count) return;
  const d = S.data, waiting = S.windowPending || !d;
  count.replaceChildren('In this window: ', el('b', {}, waiting ? '…' : d.count.toLocaleString()));
  // The links counted are those drawn: one whose ends fall in a folded group isn't, nor one from a host with no lane,
  // and the hover says how many of each
  const linkWord = d && d.links.mode === 'grouped' ? 'logon link group' : 'logon link';
  const links = [`${plural(S.linksDrawn, linkWord)} drawn`,
                 S.linksFolded && `${plural(S.linksFolded, linkWord)} inside a folded group not drawn`,
                 S.linksSkipped && `${S.linksSkipped.toLocaleString()} from a host with no lane not drawn`];
  count.title = waiting ? 'Counting the events in the new window.' :
    'Events in the window shown, under the current Sources and View, drawn one by one when few and as bars when many. ' +
    ($('showLinks').checked ? `${links.filter(Boolean).join('; ')}.` : 'Logon links are off.');
}

// A span in days, hours, minutes, and seconds to the millisecond, leaving out the parts that are zero.
export function spanText(ms) {
  const total = Math.round(ms);
  const d = Math.floor(total / 864e5), h = Math.floor((total % 864e5) / 36e5), m = Math.floor((total % 36e5) / 6e4);
  const s = (total % 6e4) / 1000;
  const parts = [d && `${d} d`, h && `${h} h`, m && `${m} min`, s && `${Number(s.toFixed(3))} s`].filter(Boolean);
  return parts.length ? parts.join(' ') : '0 s';
}
