import { $, el, plural, S, setStatus } from './core.js';
import { draw } from './draw.js';
import { markWord } from './confirm.js';
import { button, decide, loadDetails, pageAction } from './event_page.js';

// ---------- Review one by one: a source's pending suggestions, one Event page at a time ----------
// The queue is the set To investigate counted when it loaded, in time order. The Event page of an event in the queue
// draws a review bar (reviewBar): where the analyst is ("hayabusa: 3 of 5"), Accept as the suggested mark, Reject with
// its note, Next, and Stop. The keys A, R, and N do the same from anywhere on the page but a field. A review of one group of
// the Suggestions page walks the events that group counted, and its bar names the group.

let review = null;   // { source, value, queue: [uid], at: index, group }
let keysBound = false;

// `group`, for a review of one Suggestions group: `key`, its name; `place`, its page as showSuggestions takes it; and
// `answered()`, called as each decision answers. Null for a review of a whole source.
export function startReview(source, value, queue, group = null) {
  if (!queue.length) { setStatus(`Nothing is pending from ${source}.`); return; }
  review = { source, value, queue: [...queue], at: 0, group };
  bindKeys();
  openAt(0);
}

export const reviewing = () => review;

export function stopReview() {
  review = null;
}

// The review of a group whose queue holds this event, or null. Its Event pages take one place in Back's history, so Back
// from any of them returns to the group's page however long the queue, and a reload lands on that page.
export const groupReviewOf = (uid) => (review?.group && review.queue.includes(uid) ? review : null);

function openAt(i) {
  review.at = i;
  const uid = review.queue[i];
  S.selected = new Set([uid]);
  S.focus = uid;
  S.windowLinks = [];
  draw();
  loadDetails(uid);
}

// The next event of the queue, or the end: the last page draws again, and its bar says the review is done
function next() {
  if (!review) return;
  if (review.at + 1 < review.queue.length) openAt(review.at + 1);
  else { review.done = true; loadDetails(review.queue[review.at]); }
}

// The bar on an Event page whose event is in the queue; null for any other event or when no review is on.
export function reviewBar(ev, uid) {
  if (!review) return null;
  const i = review.queue.indexOf(uid);
  if (i < 0) return null;
  review.at = i;
  const n = review.queue.length;
  const pending = ev.suggestions.some((x) => x.source === review.source && !x.rejected) && ev.mark.label === 'Unreviewed';
  const note = el('input', { type: 'text', class: 'mark-note', placeholder: 'Note (optional)', 'aria-label': 'Note for the decision' });
  // The review moves on once the decision answers, unless a page was asked for meanwhile: that page keeps the panel, and
  // the review stays on this event
  const act = async (decision) => {
    const { group } = review;
    const done = pageAction(`event:${uid}`);
    const res = await decide(decision, review.source, [uid], { note: note.value, fromEvent: false });
    if (res) group?.answered();
    if (res && done(false)) next();
  };
  const stop = button('Stop reviewing', () => { stopReview(); loadDetails(uid); }, { class: 'linklike', 'data-key': 'stop' });
  const whose = review.group ? `${review.group.key} (${review.source})` : review.source;
  const where = el('strong', {}, `${whose}: ${i + 1} of ${n}`);
  if (review.done && i === n - 1) {
    return el('div', { class: 'review-bar', role: 'region', 'aria-label': 'Review one by one' },
      el('strong', {}, `${whose}: ${plural(n, 'event')} reviewed`),
      el('span', { class: 'muted' }, `That was the last of the set ${review.group ? "the group's page" : 'To investigate'} counted.`), stop);
  }
  const controls = pending
    ? [button(`Accept as ${markWord(review.value)}`, () => act('accept'), { class: `primary mark-${String(review.value).toLowerCase()}`, 'data-key': 'a' }),
       button('Reject', () => act('reject'), { 'data-key': 'r', title: 'Reject the suggestion; the note, if any, is kept with the rejection' }),
       note]
    : [el('span', { class: 'muted' }, 'Decided already.')];
  return el('div', { class: 'review-bar', role: 'region', 'aria-label': 'Review one by one' },
    where, ...controls,
    button(i + 1 < n ? 'Next ›' : 'Finish', next, { class: 'linklike', 'data-key': 'n' }),
    el('span', { class: 'muted keys' }, 'Keys: A accept, R reject, N next'), stop);
}

// A, R, and N press the bar's buttons, from anywhere but a field and without a modifier
function bindKeys() {
  if (keysBound) return;
  keysBound = true;
  document.addEventListener('keydown', (ev) => {
    if (!review || ev.ctrlKey || ev.metaKey || ev.altKey || ev.repeat) return;
    const key = ev.key.toLowerCase();
    if (!['a', 'r', 'n'].includes(key)) return;
    if (ev.target.closest && ev.target.closest('input, textarea, select, [contenteditable]')) return;
    const target = $('detailsBody').querySelector(`.review-bar [data-key="${key}"]`);
    if (!target) return;
    ev.preventDefault();
    target.click();
  });
}
