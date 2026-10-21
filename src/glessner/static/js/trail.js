import { $, el, plural, S } from './core.js';

// ---------- the pivot trail ----------
// How the analyst reached the event on screen: the event they started from, each pivot taken, and each event opened from
// a pivot's list. It lives with the tab, not the case: a new start (the timeline, a search, To investigate) begins a new
// trail, and a click on any step goes back to it. Going back keeps the later steps, dimmed, until a new pivot or another
// event replaces them: S.trailAt is the step on screen. Save trail as a note journals it as an ordinary note on
// the event the trail started from, so the reasoning path survives.

// What an event is, for a step: its code, or its evidence type.
function eventWhat(ev) {
  const channel = ev.log_channel ? ` ${ev.log_channel}` : '';
  return ev.artifact === 'evtx' ? `${ev.event_code || 'event'}${ev.logon_type ? ` type ${ev.logon_type}` : ''}`
    : ev.artifact === 'suricata' || ev.artifact === 'zeek' ? `${ev.artifact === 'zeek' ? 'Zeek' : 'Suricata'}${channel}`
    : (S.meta?.artifact_names || {})[ev.artifact] || ev.artifact;
}

// What an event is, and where.
export function eventLabel(ev) {
  const what = eventWhat(ev);
  if (ev.artifact === 'suricata' && ev.source_ip && ev.dest_ip) return `${what}, ${ev.source_ip} to ${ev.dest_ip}`;
  return `${what} on ${ev.host}${ev.artifact === 'evtx' && ev.source_ip ? ` from ${ev.source_ip}` : ''}`;
}

// The short name the save button gives the event: its code for a Windows event log, else the first part of its label.
export const eventShort = (ev) => (ev.artifact === 'evtx' ? ev.event_code || 'event' : eventWhat(ev));

// Every step carries `short` and `home`, the short name and the label of the event it is, or was taken from, so the
// save button can name the event the trail started from, which a pivot may have started.
const startTrail = (step) => { S.trail = [step]; S.trailAt = 0; };
const pushStep = (step) => { S.trail = [...S.trail.slice(0, S.trailAt + 1), step]; S.trailAt = S.trail.length - 1; };
const advanceTo = (step) => { S.trailAt += 1; S.trail[S.trailAt] = step; };

// An event page opened. `via` is true when it was opened from a pivot's list: it advances to the next step when that is this
// event, and otherwise cuts the steps after the current one and adds itself. When the panel shows an event step with the list
// of the pivot taken from it still on screen, as after going back to that step, the click continues from that pivot's step.
// `via` is 'back' when the Back link reopened the event: a step the trail holds is gone back to, keeping the others. Back
// from a page that is not a step, such as the audit trail, to the event whose pivot list is the step on screen goes back to
// nothing: the page shows that list again, and the step stays current. The same event again, as after a mark, or a step the
// analyst went back to, leaves the trail; anything else begins a new trail.
export function trailEvent(uid, ev, via) {
  const label = eventLabel(ev);
  const step = { type: 'event', uid, ts: ev.adjusted_ts_us, label, short: eventShort(ev), home: label };
  const now = S.trail[S.trailAt];
  const listOnScreen = now?.type === 'pivot' && now.uid === uid && samePivot(now, S.pivotResult?.step ?? {});
  if (via === 'back' && !listOnScreen) {
    const held = S.trail.map((s, i) => [i, s]).filter(([, s]) => s.type === 'event' && s.uid === uid)
      .sort(([i], [j]) => Math.abs(i - S.trailAt) - Math.abs(j - S.trailAt))[0];
    if (held) { S.trailAt = held[0]; S.trail[S.trailAt] = step; return; }
  }
  let at = S.trail[S.trailAt];
  const list = S.pivotResult?.step;
  // The click came from that list when the panel still shows the event it was taken from
  if (via === true && at?.type === 'event' && at.uid !== uid && list?.uid === at.uid && $('details').dataset.key === `event:${at.uid}`) {
    if (samePivot(S.trail[S.trailAt + 1] ?? {}, list)) S.trailAt += 1; else pushStep(list);
    at = S.trail[S.trailAt];
  }
  const next = S.trail[S.trailAt + 1];
  if (at && at.uid === uid) {
    if (at.type === 'event') S.trail[S.trailAt] = step;
  } else if (via === true && at && at.type === 'pivot') {
    if (next && next.type === 'event' && next.uid === uid) advanceTo(step); else pushStep(step);
  } else startTrail(step);
}

// Two pivot steps are the same when they ask the same list: the kind, the event, its size, address and term, and the source,
// scope and name that narrow it. The rank the click came from is not part of it.
const norm = (v) => String(v ?? '');
const samePivot = (a, b) => ['uid', 'kind', 'seconds', 'ip', 'term'].every((k) => norm(a[k]) === norm(b[k]))
  && ['source', 'scope', 'name'].every((k) => norm(a.more?.[k]) === norm(b.more?.[k]));

// A pivot taken from the event on screen. The one the trail has next advances to it with its new total; the pivot on screen
// run again, as after a mark or a step the analyst went back to, updates its total in place; any other pivot cuts the steps
// after the current one and adds itself. With no step for this event, the pivot starts the trail.
export function trailPivot(step) {
  const at = S.trail[S.trailAt], next = S.trail[S.trailAt + 1];
  const here = S.focusEvent && S.focusEvent.uid === step.uid ? S.focusEvent : null;
  step.short = here?.short ?? at?.short;
  step.home = here?.label ?? at?.home;
  if (!at || at.uid !== step.uid) startTrail(step);
  else if (at.type === 'pivot' && samePivot(at, step)) S.trail[S.trailAt] = step;
  else if (next && next.type === 'pivot' && samePivot(next, step)) advanceTo(step);
  else pushStep(step);
}

export const stepText = (s) => (s.type === 'pivot' && s.total != null ? `${s.label} (${s.total.toLocaleString()})` : s.label);
export const trailText = () => `Trail: ${S.trail.map(stepText).join(' > ')}`;

// The trail in the Details band, with a step for each place the analyst has been. Shown once a pivot has been taken.
// `go(i)` returns to step i, `save()` writes the trail as a note, and `current` is the step the panel shows, or -1 on a
// page that is not a step, such as Tools, where every step is a link. Steps after S.trailAt are the ones the analyst went
// back from: still links, dimmed.
export function trailBar({ go, save, current = S.trailAt }) {
  if (S.trail.length < 2) return null;
  const steps = [];
  S.trail.forEach((s, i) => {
    if (i) steps.push(el('span', { class: 'step-sep', 'aria-hidden': 'true' }, '›'));   // not .sep, the band's divider rule
    const text = stepText(s);
    const back = i > S.trailAt;
    steps.push(i === current ? el('span', { class: 'here', 'aria-current': 'step' }, text)
      : el('button', { type: 'button', class: `linklike${back ? ' dim' : ''}`,
                       title: back ? 'A step you went back from; it stays until a new pivot replaces it. Click to return to it.'
                         : s.type === 'pivot' ? `Back to this pivot's list: ${text}` : `Back to ${text}`,
                       onclick: () => go(i) }, text));
  });
  const start = S.trail[0];
  // On screen only when the panel shows its Event page: a search taken from it, or Tools, is not that
  const where = $('details').dataset.key === `event:${start.uid}` ? 'which is on screen' : 'not the one on screen';
  return el('nav', { class: 'trail', 'aria-label': 'Pivot trail' }, el('span', { class: 'muted' }, 'Trail'), ...steps,
    el('button', { type: 'button', class: 'trail-save',
                   title: `Journals the ${plural(S.trail.length, 'step')} as a note on the event the trail started from, ${start.home}, ${where}`,
                   onclick: save }, `Save trail as a note on the ${start.short} (start)`));
}
