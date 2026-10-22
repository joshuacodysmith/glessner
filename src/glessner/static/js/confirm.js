import { $, api, codePrefix, el, fmtUs, plural, S } from './core.js';

// ---------- Ask first: the confirm block before a group action ----------
// A confirm dialog as a block in the page, with the filled lead confirm and Cancel that the Hosts split's undo and the
// audit trail's Undo use. It states the action, the mark,
// the source and group, the count the page counted when it loaded, what that covers, the first few events, and how many
// arrived since and are not included. The confirm button repeats the number. Escape or Cancel changes nothing. Evidence
// text reaches it through el() only.

export const CONFIRM_ABOVE = 25;   // a hand-picked mark or tag selection asks first above this many events
const SAMPLE = 3;                  // events the block lists as "First of the N"

// Ask the analyst to confirm. `spec`: title ("Accept 1,234 hayabusa suggestions?"), `lines` (nodes or strings under it),
// `points` (the bullets), `warn` (the caution line, or ''), `events` (the first few, each { ts, host, code, msg }) with
// `count` (how many in all), `confirm` (the button's label, repeating the number), `cls` (the lead button's mark class),
// and `showAll` (a function, or null), which lists everything first and counts as a cancel. The block goes into `host`, or
// the page's `.confirm-slot`, or the top of the Details body. Resolves true on the confirm and false otherwise.
export function askConfirm(spec, host = null) {
  return new Promise((resolve) => {
    const where = host || $('detailsBody').querySelector('.confirm-slot') || $('detailsBody');
    where.querySelector(':scope > .confirm-block')?.remove();   // one question at a time in one place
    let done = false;
    const finish = (ok) => { if (done) return; done = true; block.remove(); resolve(ok); };
    const yes = el('button', { type: 'button', class: `primary ${spec.cls || ''}`.trim(), onclick: () => finish(true) }, spec.confirm);
    const actions = [yes];
    if (spec.showAll) {
      actions.push(el('button', { type: 'button', class: 'linklike', onclick: () => { finish(false); spec.showAll(); } },
                      `Show all ${spec.count.toLocaleString()} first`));
    }
    actions.push(el('button', { type: 'button', onclick: () => finish(false) }, 'Cancel'));
    const warn = [].concat(spec.warn || []);   // nodes and strings, or nothing
    const block = el('div', { class: 'confirm-block', role: 'group', 'aria-label': spec.title, tabindex: '-1' },
      el('strong', { class: 'confirm-title' }, spec.title),
      ...(spec.lines || []).map((line) => el('div', { class: 'confirm-line' }, ...[].concat(line))),
      el('ul', { class: 'confirm-points' }, ...(spec.points || []).map((p) => el('li', {}, ...[].concat(p)))),
      ...(warn.length ? [el('div', { class: 'confirm-warn' }, ...warn)] : []),
      ...sample(spec.events || [], spec.count),
      el('div', { class: 'actions' }, ...actions));
    block.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') { ev.stopPropagation(); finish(false); } });
    if (where === $('detailsBody')) where.prepend(block); else where.append(block);
    yes.focus();
  });
}

// "First of the N": up to SAMPLE events, one line each, then "and K more"
function sample(events, count) {
  if (!events.length) return [];
  const shown = events.slice(0, SAMPLE);
  const rest = count - shown.length;
  return [el('h3', {}, count > shown.length ? `First of the ${count.toLocaleString()}` : plural(count, 'event')),
          el('div', { class: 'confirm-sample' },
             ...shown.map((e) => el('div', {}, `${e.ts == null ? 'no time' : fmtUs(e.ts).slice(0, 19)}  ${e.host}  ${codePrefix(e)}${e.msg}`)),
             ...(rest > 0 ? [el('div', { class: 'muted' }, `and ${rest.toLocaleString()} more`)] : []))];
}

const MARK_WORD = { malicious: 'Malicious', suspicious: 'Suspicious', authorized: 'Authorized' };
// A mark as the page writes it everywhere else, capitalized, from the lower-case value a suggestion or a request carries
export const markWord = (value) => MARK_WORD[String(value).toLowerCase()] || value;
const clock = (date) => `${date.toISOString().slice(11, 19)} UTC`;

// What the server answers to a decision naming more events than one journal entry can hold (server._decide), and what
// to do instead: a group's decision regroups, and any other goes a group at a time.
function tooManyWords(decision, total, limit, grouped) {
  const accept = decision === 'accept';
  const head = accept
    ? `Accepting these would mark ${total.toLocaleString()} events, more than the ${limit.toLocaleString()} a mark can hold.`
    : `Rejecting these would name ${total.toLocaleString()} events, more than the ${limit.toLocaleString()} one decision can name.`;
  const fewer = grouped
    ? `Group the suggestions another way, by rule, host, account, or event ID, and ${accept ? 'accept' : 'reject'} smaller groups.`
    : `${accept ? 'Accept' : 'Reject'} them a group at a time from the source's Suggestions page.`;
  return `${head} ${fewer}`;
}

// A refusal in the place the confirm block would go, with Close
function showRefusal(text, host) {
  const where = host || $('detailsBody').querySelector('.confirm-slot') || $('detailsBody');
  where.querySelector(':scope > .confirm-block')?.remove();
  const block = el('div', { class: 'confirm-block', role: 'alert', tabindex: '-1' },
    el('div', { class: 'confirm-line' }, text),
    el('div', { class: 'actions' }, el('button', { type: 'button', onclick: () => block.remove() }, 'Close')));
  if (where === $('detailsBody')) where.prepend(block); else where.append(block);
}

// The question before Accept all, Reject all, or a group's Accept N or Reject N, on the Suggestions page or To investigate.
// `uids` is the set the page counted when it loaded (`loadedAt`), `listed` how many of them the page lists, `first` the
// first few events, `group` and `groupBy` the group when the action is one group's, `value` what the source suggests. The
// events pending now are read first, so the block can say how many arrived after the page loaded (not included) and how
// many of the counted were decided elsewhere meanwhile (skipped by the server). Resolves to the confirmed uids, or null.
// `total` is how many events the action covers when the page holds the IDs of fewer, as To investigate does for a source
// with more pending than one decision can name; above that limit the action is refused here, in the server's words and
// before anything is fetched or sent.
export async function askGroupDecision({ decision, source, value, group = null, groupBy = '', uids, total = uids.length, listed,
                                         first, loadedAt, showAll = null, host = null }) {
  const limit = S.meta?.max_mark_targets;
  if (limit && total > limit) {
    showRefusal(tooManyWords(decision, total, limit, group != null), host);
    return null;
  }
  const n = uids.length;
  let now = null;
  try {
    const q = `source=${encodeURIComponent(source)}` + (group != null ? `&group_by=${groupBy}&group=${encodeURIComponent(group)}` : '');
    now = new Set((await api(`/api/pending_uids?${q}`)).uids);
  } catch (_) { /* without it the block says nothing of what arrived since */ }
  const counted = new Set(uids);
  const arrived = now ? [...now].filter((u) => !counted.has(u)).length : 0;
  const gone = now ? uids.filter((u) => !now.has(u)).length : 0;
  const verb = decision === 'accept' ? 'Accept' : 'Reject';
  const word = markWord(value);
  const what = group != null ? [el('b', {}, group), ` (${groupBy})`] : [el('b', {}, source)];
  const where = group != null ? 'Group: ' : 'Source: ';
  const covers = listed >= n ? `every one is listed on this page.`
    : listed ? `the ${listed.toLocaleString()} listed on this page and the ${(n - listed).toLocaleString()} counted but not listed.`
      : 'none is listed on this page; the first are shown below.';
  const points = [
    decision === 'accept'
      ? ['All ', el('b', {}, n.toLocaleString()), ' are marked ', el('b', {}, word), `: ${covers}`]
      : ['All ', el('b', {}, n.toLocaleString()), ` stay Unreviewed, and ${source} stops suggesting them: ${covers}`],
    'The journal records this as one entry listing every event, with your name and the time.',
  ];
  const warn = [];
  if (arrived) {
    warn.push(el('b', {}, `${arrived.toLocaleString()} more`), ` ${arrived === 1 ? 'suggestion' : 'suggestions'} for this `,
              `${group != null ? 'group' : 'source'} arrived after the page loaded. ${arrived === 1 ? 'It is' : 'They are'} `,
              el('b', {}, 'not'), ` included. Reload the page to review ${arrived === 1 ? 'it' : 'them'}.`);
  }
  if (gone) {
    warn.push(...(warn.length ? [' '] : []), `${gone.toLocaleString()} of the ${n.toLocaleString()} ${gone === 1 ? 'was' : 'were'} decided `
              + 'elsewhere since the page loaded and will be skipped.');
  }
  const ok = await askConfirm({
    title: `${verb} ${plural(n, `${source} suggestion`)}?`,
    lines: [[where, ...what, `, counted when this page loaded at ${clock(loadedAt)}.`]],
    points, warn, events: first, count: n, confirm: `${verb} ${(n - gone).toLocaleString()}`,   // what the server will act on: the counted less those decided elsewhere
    cls: decision === 'accept' ? `mark-${String(value).toLowerCase()}` : '', showAll,
  }, host);
  return ok ? uids : null;
}

// The question before a mark or a tag of a hand-picked selection above CONFIRM_ABOVE events (the timeline's selection,
// a pivot or search list's ticks). `action` is "Mark 30 events Suspicious" or "Tag 30 events: Lateral Movement".
// `events` lists the first few when the caller has them; otherwise they are read. `effect` words what happens to the
// events when it is not a change to them: a link to a finding changes no mark and no tag.
export async function askSelection({ action, uids, events = null, cls = '', host = null, effect = '' }) {
  const n = uids.length;
  let first = events;
  if (!first) {
    try { first = (await api(`/api/selected?${uids.slice(0, SAMPLE).map((u) => `uid=${encodeURIComponent(u)}`).join('&')}`)).events; }
    catch (_) { first = []; }
  }
  return askConfirm({
    title: `${action}?`,
    lines: [`A selection of ${plural(n, 'event')} you picked by hand.`],
    points: [effect || `All ${n.toLocaleString()} change.`, 'The journal records this as one entry listing every event, with your name and the time.'],
    warn: '', events: first, count: n, confirm: `${action.split(' ')[0]} ${n.toLocaleString()}`, cls,
  }, host);
}
