import { askGroupDecision, askSelection, CONFIRM_ABOVE, markWord, rejectMeans } from './confirm.js';
import { api, codePrefix, el, fmtUs, LISTED_EVENTS, lookup, markBadge, plural, S, setStatus } from './core.js';
import { draw } from './draw.js';
import { button, claimDetails, decide, pageAction, pageAnswered, pageRead, setPage } from './event_page.js';
import { jumpTo, listFind } from './pages.js';
import { startReview } from './review.js';
import { ruleTerm, typedSearch } from './search.js';

// ---------- Suggestions page: one source's pending suggestions, grouped, or one group alone as a page of its own ----------

// 'rule' groups Hayabusa hits by rule title, and Suricata alerts and imported fast alerts by signature.
export const GROUP_BY = [['rule', 'Rule or signature'], ['account', 'Account'], ['host', 'Host'], ['code', 'Event ID']];

// The page last drawn, as showSuggestions takes it, so a reload can draw it again
let shown = null;
export const shownSuggestions = () => shown;

// The key of the page with a source's groups, which regrouping keeps, and of the page with one group alone
const groupsKey = (source) => `suggestions:${source}`;
const groupPageKey = (source, groupBy, group) => `${groupsKey(source)}:${groupBy}:${group}`;
const groupsTitle = (source) => `${source} suggestions`;

// The key of the Suggestions page asked for last
let askedKey = null;

// Tell the Suggestions page asked for last that a decision has answered, unless it is `made`, the page that says so itself. Back
// or a group's title can ask for it while the decision is out, and its read may not show the decision, so its counts would be
// false until it draws again. That holds for another source's page too: an accept marks the event, which then leaves every
// source's pending events.
function answerLastAsked(made = null) {
  if (askedKey !== made) pageAnswered(askedKey);
}

// A control that opens a page calls this as it acts. The second click of a double click lands on the control again, or on
// whatever the new page has drawn under the pointer by then, so the next click does nothing when it is that second click.
const dropSecondClick = () => document.addEventListener('click', (ev) => {
  if (ev.detail > 1) ev.stopImmediatePropagation();
}, { capture: true, once: true });

// Whether the group named `name` is open on the page with this key: as the page first drew it, which `byDefault` says, or
// as its arrow last set it. A decision draws the page again with every group as it was, wherever the new order puts it.
function groupOpen(key, name, byDefault) {
  if (S.folds.key !== key) S.folds = { key, open: new Map() };
  if (!S.folds.open.has(name)) S.folds.open.set(name, byDefault);
  return S.folds.open.get(name);
}

// The rows decided one at a time or by their ticks on the page with this key, by event ID, the latest LISTED_EVENTS of them,
// which is how many a read can name. Each is the event as the page listed it, with its `decision`, the `mark` an accept gave,
// the `groupBy` it was listed under, and its `group`: the group's head, and `at`, the group's place on the page.
function decidedRows(key) {
  if (S.decided.key !== key) S.decided = { key, rows: new Map() };
  return S.decided.rows;
}

// Whether a decided row's label still holds of its event, as a read found the event: an accepted one keeps the mark the
// decision gave it, and a rejected one stays rejected and unmarked.
const stillTrue = (row, state) => (row.decision === 'accept' ? state.mark === row.mark : state.rejected && !state.mark);

// Take off the page each row whose label is no longer true: the timeline's marks and the right-click menu change an event
// without drawing this page. A row decided after the read went out has no state in the read, which can't speak for it.
function dropFalseRows(rows, states) {
  for (const [uid, row] of rows) {
    const state = lookup(states, uid);
    if (state && !stillTrue(row, state)) rows.delete(uid);
  }
}

// A group's rows in the server's order: by time, an event with none last, and ties by ID.
const listOrder = (a, b) => (a.ts ?? Infinity) - (b.ts ?? Infinity) || (a.uid < b.uid ? -1 : a.uid > b.uid ? 1 : 0);

// The groups to draw, each with `rows`: its pending events and its decided rows, each where it sat. A group with only
// decided rows left keeps the place it had, with a count of 0. An event that a read older than its decision still lists
// draws as pending until the redraw the decision owes.
function withDecided(groups, decided) {
  const pending = new Set(groups.flatMap((g) => g.events.map((e) => e.uid)));
  const kept = new Map();
  for (const row of decided) {
    if (pending.has(row.uid)) continue;
    if (!kept.has(row.group.key)) kept.set(row.group.key, []);
    kept.get(row.group.key).push(row);
  }
  const drawn = groups.map((g) => ({ ...g, rows: [...g.events, ...(kept.get(g.key) || [])].sort(listOrder) }));
  const listed = new Set(groups.map((g) => g.key));
  const left = [...kept].filter(([name]) => !listed.has(name))
    .map(([, rows]) => ({ ...rows[rows.length - 1].group, count: 0, events: [], rows: [...rows].sort(listOrder) }))
    .sort((a, b) => a.at - b.at);
  for (const g of left) drawn.splice(g.at, 0, g);
  return drawn;
}

// The page's ticks by group's key, as the read's `groups` leave them. A tick stays only on an event the read lists as pending
// in that group, so a rule changing or a decision made elsewhere takes it off. Regrouping starts them again, since another
// grouping's groups hold other events.
function standingTicks(key, groupBy, groups) {
  if (S.ticks.key !== key || S.ticks.groupBy !== groupBy) S.ticks = { key, groupBy, groups: new Map() };
  const listed = new Map(groups.map((g) => [g.key, new Set(g.events.map((e) => e.uid))]));
  for (const [name, ticks] of S.ticks.groups) {
    for (const uid of ticks) if (!listed.get(name)?.has(uid)) ticks.delete(uid);
  }
  return S.ticks.groups;
}

// The groups, by their Sets of ticks, whose ticked decision is out, from its request until its answer is handled. A second
// click sends nothing: the request would name the same events again, and its answer would replace the first's on the status
// line. The Set outlives a redraw, so a button drawn meanwhile is covered too.
const ticksOut = new WeakSet();

// Each group's Set of ticks, with the controls on screen for it, the latest drawn
const drawnTicks = new WeakMap();

// Take events off the page's ticks. A group that loses one closes its open question and draws its head again, as a tick's
// click does: an action that isn't a click on a tick can change them too.
function untick(uids) {
  for (const ticks of S.ticks.groups.values()) {
    const had = ticks.size;
    for (const uid of uids) ticks.delete(uid);
    if (ticks.size !== had) drawnTicks.get(ticks)?.changed();
  }
}

// A button that reads what `say` sets and keeps the width of `room`, its longest label, in a hidden span in the same grid cell
const roomyButton = (room, onclick, attrs = {}) => {
  const node = button(el('span', {}), onclick, attrs);
  node.append(el('span', { class: 'sg-room', 'aria-hidden': 'true' }, room));
  return node;
};
const say = (node, text) => { node.firstChild.textContent = text; };

// One group's ticks, drawn from `ticks`, its Set, on `uids`, the events it lists. `box(uid)` is a pending row's tick, in a label
// that fills the row's left edge, so a click just off the box ticks and doesn't open the event. `head` holds the select button,
// as on the other ticked lists (pages.markableList), and Accept N ticked and Reject N ticked, which call `act(decision)`. Each
// keeps the room of its longest label, the two hidden while nothing is ticked, so a tick or the select button moves no row
// under the pointer. The button reaches the rows the group lists: with `cut`, some aren't listed, so it says how many it
// reaches. `note` says how many ticks a find hides, and `findShows(set)` takes the rows it shows, or null with no find: the
// button then ticks or unticks those only. `asked(block)` names the question on screen for the ticks, and `changed()`, for
// any change of them, takes it away, since it stated other events, and draws the head and the boxes again, as `show()` does.
function tickControls(ticks, uids, cut, acceptClass, act) {
  const boxes = new Map();
  const listed = new Set(uids);
  const count = uids.length.toLocaleString();
  let inFind = null;
  let question = null;
  const reach = () => inFind || listed;
  const everyReachedTicked = () => reach().size > 0 && [...reach()].every((uid) => ticks.has(uid));
  const selectLabel = () => {
    if (!inFind && !cut) return everyReachedTicked() ? 'Select none' : 'Select all';
    return `${everyReachedTicked() ? 'Unselect' : 'Select'} the ${reach().size.toLocaleString()} shown`;
  };
  const note = el('span', { class: 'find-ticks', hidden: '' });
  const accept = roomyButton(`Accept ${count} ticked`, () => act('accept'), { class: acceptClass });
  const reject = roomyButton(`Reject ${count} ticked`, () => act('reject'));
  const show = () => {
    const out = inFind ? [...ticks].filter((uid) => !inFind.has(uid)).length : 0;
    note.hidden = !out;
    note.textContent = out ? `${plural(out, 'ticked event')} ${out === 1 ? "isn't" : "aren't"} shown here` : '';
    say(select, selectLabel());
    select.disabled = !reach().size;
    for (const [word, node] of [['Accept', accept], ['Reject', reject]]) {
      say(node, `${word} ${ticks.size.toLocaleString()} ticked`);
      node.classList.toggle('none-ticked', !ticks.size);
      node.disabled = ticksOut.has(ticks);
    }
    for (const [uid, box] of boxes) box.checked = ticks.has(uid);
  };
  const changed = () => { question?.remove(); show(); };
  const select = roomyButton(cut ? `Unselect the ${count} shown` : 'Select none', () => {
    const every = everyReachedTicked();
    for (const uid of reach()) { if (every) ticks.delete(uid); else ticks.add(uid); }
    changed();
  });
  const box = (uid) => {
    const tick = el('input', { type: 'checkbox', 'aria-label': 'Tick to accept or reject' });
    tick.checked = ticks.has(uid);
    tick.addEventListener('change', () => { if (tick.checked) ticks.add(uid); else ticks.delete(uid); changed(); });
    boxes.set(uid, tick);
    return el('label', { class: 'sg-tick', onclick: (ev) => ev.stopPropagation() }, tick);
  };
  show();
  const controls = { box, note, show, changed, head: el('span', { class: 'sg-ticks' }, select, accept, reject),
                     findShows: (set) => { inFind = set; show(); }, asked: (block) => { question = block; } };
  drawnTicks.set(ticks, controls);
  return controls;
}

// A group's page after a reload, which loses Back's history: Back leads to the page with the source's groups again.
export function reopenGroupPage(source, groupBy, limit, group) {
  S.back.push({ key: groupsKey(source), title: groupsTitle(source), reopen: () => showSuggestions(source, groupBy), group: null });
  return showSuggestions(source, groupBy, limit, group);
}

// `limit` lists more than the first 200 of each group, for the confirm's "Show all N first". `only`, a group's key under
// `groupBy`, draws that group alone: a page of its own, led by Review one by one over the events the group counts.
export async function showSuggestions(source, groupBy = '', limit = 0, only = null) {
  const latest = claimDetails();   // a page asked for after it keeps the panel
  const drew = pageRead();
  const onePage = only !== null;
  const key = onePage ? groupPageKey(source, groupBy, only) : groupsKey(source);
  askedKey = key;
  // The read says what has become of the events kept as decided, as other pages can change them
  const named = S.decided.key === key ? [...S.decided.rows.keys()].map((uid) => `&decided=${encodeURIComponent(uid)}`).join('') : '';
  let res;
  try { res = await api(`/api/pending?source=${encodeURIComponent(source)}${groupBy ? `&group_by=${groupBy}` : ''}${limit ? `&limit=${limit}` : ''}${named}`); }
  catch (err) { setStatus(err.message); return; }
  if (!latest()) return;
  groupBy = res.group_by;
  const listedGroups = onePage ? res.groups.filter((g) => g.key === only) : res.groups;
  dropFalseRows(decidedRows(key), res.decided);
  const ticksByGroup = standingTicks(key, groupBy, listedGroups);
  shown = { source, groupBy, limit, group: only };
  const loadedAt = new Date();   // what the confirm names as when the page counted
  // Rows keep to the grouping they were decided under: another grouping's groups can't be told from what a row holds
  const decided = [...decidedRows(key).values()].filter((row) => row.groupBy === groupBy);
  const value = listedGroups.length ? listedGroups[0].events[0].value : decided[0]?.value ?? '';
  const refresh = () => showSuggestions(source, groupBy, limit, only);
  // A decision goes out. What this returns, called on its answer, draws the page again, not over a page asked for while the
  // decision was made, and tells the source's page asked for last.
  const decisionOut = () => {
    const done = pageAction(key);
    return () => { done(); answerLastAsked(key); };
  };
  const act = async (decision, opts) => {
    const done = decisionOut();
    await decide(decision, source, opts.uids || null, { ...opts, fromEvent: false });
    done();
  };
  // Keep a decided row on the page. An accept's mark is the one the server gave, which a rule changed since the page drew can
  // make another than listed; where it gave several, the row's own, as listed.
  const keepRow = (decision, e, group, answer) => {
    const { rows } = S.decided;
    const given = Object.keys(answer.accepted || {});
    const mark = markWord(given.length > 1 && given.includes(e.value) ? e.value : given[0]);
    rows.set(e.uid, { ...e, decision, groupBy, group, mark });
    if (rows.size > LISTED_EVENTS) rows.delete(rows.keys().next().value);
  };
  // One event acts at once. Its row stays on the page as decided, and Restore puts it back to pending. A decision the server
  // didn't make, or a reject of an event marked meanwhile, leaves no row to label: the redraw drops it.
  const actOnRow = async (decision, e, group) => {
    const done = decisionOut();
    const answer = await decide(decision, source, [e.uid], { fromEvent: false });
    if (answer) untick([e.uid]);
    if (answer && S.decided.key === key) {
      if (decision === 'restore') S.decided.rows.delete(e.uid);
      else if (answer.changed && !answer.marked) keepRow(decision, e, group, answer);
    }
    done();
  };
  // Accept N ticked or Reject N ticked, on the group's rows ticked at the click. It acts at once or, above CONFIRM_ABOVE events,
  // once the analyst confirms them as hand-picked, and the entry then carries the count stated. Either way the server acts on
  // those still pending and says how many it skipped. The rows stay on the page as decided, as a row decided on its own does.
  // An answer doesn't say which events it skipped, so all are kept, but for a row already kept with its own decision, and the
  // redraw's read drops those whose label is false. A decision the server refused keeps the ticks for another try.
  const actOnTicked = async (decision, events, group, ticks, host) => {
    if (ticksOut.has(ticks)) return;
    const chosen = events.filter((e) => ticks.has(e.uid));
    const uids = chosen.map((e) => e.uid);
    const accepting = decision === 'accept';
    const consent = {};
    if (uids.length > CONFIRM_ABOVE) {
      const n = uids.length.toLocaleString();
      const asked = askSelection({
        action: `${accepting ? 'Accept' : 'Reject'} ${plural(uids.length, `${source} suggestion`)}`,
        uids, events: chosen, host, cls: accepting ? `mark-${value}` : '',
        effect: accepting ? `All ${n} are marked ${markWord(value)}.` : `All ${n} stay Unreviewed, and ${source} stops suggesting them.`,
      });
      // Given its events, the question draws as it is asked
      drawnTicks.get(ticks)?.asked(host.querySelector(':scope > .confirm-block'));
      if (!await asked) return;
      consent.confirmed = { count: uids.length };
    }
    const done = decisionOut();
    ticksOut.add(ticks);
    drawnTicks.get(ticks)?.show();
    let answer;
    try { answer = await decide(decision, source, uids, { ...consent, pendingOnly: true, fromEvent: false }); }
    finally { ticksOut.delete(ticks); }
    if (answer) {
      untick(uids);
      if (answer.changed && S.decided.key === key) {
        for (const e of chosen) if (!S.decided.rows.has(e.uid)) keepRow(decision, e, group, answer);
      }
    }
    drawnTicks.get(ticks)?.show();
    done();
  };
  const rowText = (e) => el('span', { class: 'sg-text' }, `${fmtUs(e.ts)}  ${e.host}  ${codePrefix(e)}${e.msg}`);
  const pendingRow = (e, group, tick) => el('li', { 'data-uid': e.uid, onclick: () => jumpTo(e) },
    tick(e.uid),
    markBadge({ mark: `Suggested: ${e.value}`, suggest_source: source }),   // every pending event is unreviewed, with this guess
    rowText(e),
    button('Accept', (ev) => { ev.stopPropagation(); actOnRow('accept', e, group); }),
    button('Reject', (ev) => { ev.stopPropagation(); actOnRow('reject', e, group); }));
  // The label spells the state out, so the row carries no badge
  const decidedRow = (row) => el('li', { class: 'sg-decided', onclick: () => jumpTo(row) }, rowText(row),
    el('span', { class: 'sg-decision' }, row.decision === 'accept' ? `Accepted as ${row.mark}` : 'Rejected, stays Unreviewed'),
    ...(row.decision === 'reject' ? [button('Restore', (ev) => { ev.stopPropagation(); actOnRow('restore', row); })] : []));
  // Accept all, Reject all, and a group's Accept N or Reject N ask first: the question names the exact events the
  // page counted when it loaded, and the decision then covers those, not whatever is pending at the click
  const askThen = async (decision, { uids, listed, first, group = null, showAll, host }) => {
    const chosen = await askGroupDecision({ decision, source, value, group, groupBy, uids, listed, first, loadedAt, showAll, host });
    if (chosen) await act(decision, { uids: chosen, confirmed: { count: chosen.length } });
  };
  // The pending events listed stand out on the timeline, as related events do after a pivot.
  S.related = new Set(listedGroups.flatMap((g) => g.events.map((e) => e.uid)));
  S.windowLinks = [];
  draw();
  const groupSelect = el('select', { onchange: () => showSuggestions(source, groupSelect.value) },
    ...GROUP_BY.map(([k, label]) => { const o = el('option', { value: k }, label); if (k === groupBy) o.selected = true; return o; }));
  const expandAll = res.total <= 50;
  const listed = res.groups.reduce((n, g) => n + g.events.length, 0);
  const everyUid = res.groups.flatMap((g) => g.uids || []);
  const firstOfAll = res.groups.flatMap((g) => g.events).sort((a, b) => (a.ts ?? Infinity) - (b.ts ?? Infinity)).slice(0, 3);
  const deciding = `Accept marks the events ${value}. ${rejectMeans(source)} ` +
    'Tick rows to decide only those: Accept N ticked and Reject N ticked act at once, and ask first above 25. ' +
    `A row decided on its own or by its tick stays here, dimmed, until you leave the page (the latest ${LISTED_EVENTS} such rows), ` +
    'and a rejected one has Restore. ';
  // A Suricata group reads "severity 1" and a fast alert group "priority 1", in the alert's own words, colored as the level
  // it ranks with.
  const levelChip = (g) => (g?.level ? [el('span', { class: `chip level-${g.level}` }, g.level_label || g.level)] : []);
  const drawnGroups = withDecided(listedGroups, decided);
  const groups = drawnGroups.map((g, i) => {
    const n = g.count.toLocaleString();
    const head = { key: g.key, level: g.level, level_label: g.level_label, at: i };
    const box = el('div', { class: 'sg-group' });
    if (!ticksByGroup.has(g.key)) ticksByGroup.set(g.key, new Set());
    const ticks = ticksByGroup.get(g.key);
    const controls = tickControls(ticks, g.events.map((e) => e.uid), g.count > g.events.length, `mark-${value}`,
                                  (decision) => actOnTicked(decision, g.events, head, ticks, box));
    const body = el('ul', { class: 'sg-events' },
                    ...g.rows.map((row) => (row.decision ? decidedRow(row) : pendingRow(row, head, controls.box))));
    if (g.count > g.events.length) {
      const walks = onePage ? 'Review one by one walks all of them; ' : '';
      body.append(el('li', { class: 'muted sg-more' }, `Showing the first ${g.events.length} of ${n}. Ticks reach these rows; ${walks}` +
                                                       `Accept ${n} and Reject ${n} cover all of them, and ask first.`));
    }
    const name = `group:${groupBy}:${g.key}`;   // the group's find box and fold are kept under it
    // The find box, by group; a group cut at the limit says how far it reaches. Its line sits over the list, inside
    // the fold with it. It finds decided rows too, and its counts, like the group's, cover pending events. A group with
    // none pending has no find, so nothing hides the rows it has left.
    const find = g.count ? listFind(body, { page: key, name, rows: 'li:not(.sg-more)', uncounted: '.sg-decided',
                                            cells: '.sg-text', highlight: '.sg-text', covers: "The group's count and whole-group buttons still cover",
                                            listed: g.count > g.events.length ? g.events.length : null, total: g.count, more: 'events',
                                            onApply: controls.findShows }) : null;
    find?.box.append(controls.note);
    find?.box.querySelector('input').setAttribute('data-find', name);   // how a redraw finds the box again
    // On the group's own page the help sits under the head, which leads the page even in a short, narrow panel
    const help = onePage ? [el('p', { class: 'muted' }, 'Review one by one opens each pending event of this group on its Event page in turn: ' +
                               `A accepts, R rejects, N moves on. ${deciding}` +
                               'Accept N and Reject N cover every event the page counted, and ask first. Click an event to open it.')] : [];
    const fold = el('div', { class: 'sg-body', id: `sgFold${i}` }, ...help, ...(find ? [find.foot] : []), body);
    const open = onePage || groupOpen(key, name, expandAll || i === 0);
    fold.hidden = !open;
    const twisty = button(open ? '▾' : '▸', () => {
      fold.hidden = !fold.hidden;
      S.folds.open.set(name, !fold.hidden);
      twisty.textContent = fold.hidden ? '▸' : '▾';
      twisty.setAttribute('aria-expanded', String(!fold.hidden));
    }, { class: 'twisty', 'aria-label': `Show or hide ${g.key}`, 'aria-expanded': String(open), 'aria-controls': fold.id });
    // Show all first lists the whole group, up to the server's cap, and opens it
    const showAll = g.count > g.events.length ? () => { S.folds.open.set(name, true); showSuggestions(source, groupBy, g.count, only); } : null;
    const counted = g.uids || g.events.map((e) => e.uid);
    const ask = (decision) => askThen(decision, { uids: counted, listed: g.events.length,
                                                  first: g.events.slice(0, 3), group: g.key, showAll, host: box });
    // Among the groups, the head starts with the group's fold and its title, which opens it alone. On its own page, the page's
    // heading names it, and the review leads the head, over every event the group counts, which can be more than it lists.
    const opening = onePage ? [] : [
      twisty,
      button(el('strong', {}, g.key), () => { dropSecondClick(); showSuggestions(source, groupBy, limit, g.key); },
             { class: 'linklike sg-title', title: 'Open this group alone, to review its events one by one' }),
      ...levelChip(g),
    ];
    const review = onePage ? [button('Review one by one', () => {
      dropSecondClick();
      startReview(source, value, counted, { key: g.key, place: { source, groupBy, limit, group: only },
                                            answered: () => answerLastAsked() });
    }, { class: 'primary', title: `Open each of the ${plural(g.count, 'pending event')} on its Event page in turn` })] : [];
    box.append(
      el('div', { class: 'sg-head' }, ...opening,
         el('span', { class: 'muted' }, `${n} pending`),
         ...(g.count ? [...review, button(`Accept ${n}`, () => ask('accept'), { class: `mark-${value}` }),
                        button(`Reject ${n}`, () => ask('reject')), controls.head] : []),
         ...(find ? [find.box] : [])),
      fold);
    return box;
  });
  const slot = el('div', { class: 'confirm-slot' });   // where the page-wide question goes, under the buttons
  const top = el('div', { class: 'actions' },
    ...(res.total ? [
      button('Accept all', () => askThen('accept', { uids: everyUid, listed, first: firstOfAll, host: slot,
                                                     showAll: listed < res.total ? () => showSuggestions(source, groupBy, res.total) : null }),
             { class: `mark-${value}` }),
      button('Reject all', () => askThen('reject', { uids: everyUid, listed, first: firstOfAll, host: slot,
                                                     showAll: listed < res.total ? () => showSuggestions(source, groupBy, res.total) : null })),
    ] : []),
    el('span', { class: 'muted' }, 'Group by'), groupSelect);
  const groupsPage = () => [
    el('h2', {}, `${source} suggests ${value || 'a mark'}: ${res.total.toLocaleString()} pending`),
    top, slot,
    el('p', { class: 'muted' }, `${deciding}` +
       'Accept all, Reject all, and a group\'s Accept N and Reject N cover every event the page counted, and ask first. ' +
       'Click a group\'s title to open it alone, with Review one by one over its events. Click an event to open it.'),
    ...(res.total ? [] : [el('p', {}, 'Nothing is pending from this source.')]),
    ...groups,
  ];
  // The rule search reaches the events the rule hit whatever became of them, and those the group's count leaves out: those
  // decided, and those filed under a more severe rule that hit them too. A signature, a grouping not by rule, and a title that
  // search can't name alone have none.
  const term = onePage && source === 'hayabusa' && groupBy === 'rule' ? ruleTerm(only) : null;
  const groupPage = () => [
    el('h2', { class: 'sg-name' }, el('span', {}, only), ...levelChip(drawnGroups[0])),
    el('p', {}, `${source} suggests ${value || 'a mark'}`,
       ...(term ? [' · ', button('Every event this rule hit, in any state', () => { dropSecondClick(); typedSearch(term); },
                                 { class: 'linklike', title: `Search for ${term}` })] : [])),
    ...(groups.length ? groups : [el('p', {}, 'Nothing is pending in this group.')]),
  ];
  // A redraw draws new find boxes, so the one in use gets back the focus and its caret
  const typing = document.activeElement;
  const typedIn = typing?.dataset.find;
  setPage('suggestions', onePage ? groupPage() : groupsPage(),
          { key, title: onePage ? `${source}: ${only}` : groupsTitle(source), reopen: refresh });
  if (typedIn) {
    const box = document.querySelector(`#details input[data-find="${CSS.escape(typedIn)}"]`);
    box?.focus();
    box?.setSelectionRange(typing.selectionStart, typing.selectionEnd);
  }
  drew(key, refresh);
}
