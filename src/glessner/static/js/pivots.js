import { api, el, plural, post, S, setStatus } from './core.js';

// ---------- next pivots on the Event page ----------
// The server ranks the pivots for the event's kind from the table in pivots.py: each row has the
// pivot and its value, a reason, the reasons it is broad, and a caveat where today's matching misses what the reason
// promises. The rows draw at once; each row's count, and the top sources of the window's and of any row over the list's
// limit, follow in requests of their own, which the next Event page cancels. The page guides and never decides: the
// analyst picks the pivot. Evidence text reaches the page only through el(), which sets text, never HTML.

const NUMBER = (n) => n.toLocaleString();
// The table's label for the window, "Same host within ±N s", as the button reads before its box: "Same host within ±"
const windowLabel = (label) => label.replace(/ ±N s$/, ' ±');
const eventsText = (n) => plural(n, 'event');

let turn = 0;               // the count requests of the page drawn last; older answers are dropped
let counting = null;        // their AbortController

// The reasons fold: "Show reasons" opens or folds every row's reason, flags, and caveat at once, and is
// remembered in this browser (absent means open). A row's own toggle overrides it for that row. Those overrides are kept per
// event, through a redraw of the same event such as a mark's, and dropped when another event's panel draws; they are not stored.
const REASONS_KEY = 'glessner.showReasons';
let reasonsOpen = null;
function showReasons() {
  if (reasonsOpen === null) {
    try { reasonsOpen = localStorage.getItem(REASONS_KEY) !== '0'; } catch (_) { reasonsOpen = true; /* storage blocked */ }
  }
  return reasonsOpen;
}
function keepReasons(open) {
  reasonsOpen = open;
  try { localStorage.setItem(REASONS_KEY, open ? '1' : '0'); } catch (_) { /* kept for this page only */ }
}
const overrides = new Map();   // uid and row key to 'folded' or 'unfolded', where the row differs from the section
let overridesUid = null;

// The query a row's pivot is asked with, as /api/related and /api/pivot_count take it.
export function rowQuery(uid, at, row, more = {}) {
  const q = { uid, kind: row.pivot, ts: at, ip: row.ip, seconds: row.pivot === 'window' || row.pivot === 'connection' ? row.seconds : '',
              term: row.term, name: row.name, ...more };
  return Object.entries(q).filter(([, v]) => v !== '' && v != null).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
}

// The panel for one event: `ev` is the /api/event answer, `act` the page's actions: run(row, more), search(term), and
// editWindow(row, seconds) which returns the new size or null.
export function pivotPanel(ev, uid, act) {
  const g = ev.pivots;
  if (counting) counting.abort();
  counting = new AbortController();
  if (g.error) {   // the server's own fault, shown where the pivots would be, beside an event that loaded
    return el('section', { class: 'pivots', 'aria-label': 'Next pivots' }, el('h3', {}, 'Next pivots'),
              el('p', { class: 'muted' }, `Not available for this event: ${g.error}`));
  }
  const mine = ++turn;
  if (overridesUid !== uid) { overrides.clear(); overridesUid = uid; }
  const ctx = { uid, at: ev.adjusted_ts_us, g, act, signal: counting.signal, mine, open: showReasons(), states: [] };
  const rows = g.rows.map((row) => pivotRow(row, ctx));
  const notOffered = g.not_offered.length
    ? el('p', { class: 'pv-not' }, el('strong', {}, 'Not offered for this event: '),
        ...g.not_offered.flatMap((n, i) => [...(i ? [' '] : []), `${n.label}: ${n.reason.replace(/\.?$/, '.')}`]))
    : null;
  const plain = g.plain.length
    ? el('p', { class: 'pv-plain' }, el('strong', {}, 'Also: '), ...g.plain.flatMap((p, i) => [...(i ? [' · '] : []), ...plainLink(p, ctx)]))
    : null;
  const tick = el('input', { type: 'checkbox' });
  tick.checked = ctx.open;
  const section = el('section', { class: `pivots${ctx.open ? '' : ' reasons-folded'}`, 'aria-label': 'Next pivots' },
    el('div', { class: 'pv-h' },
       el('h3', { title: 'In the order the fixed guidance table gives for this kind of event, which cites its sources. Counts run ' +
                         'when the page opens, over the whole case, not the View; the click lists the 500 nearest in time.' },
          `Next pivots for ${g.title}`),
       el('label', { title: "Show every row's reason, its flags, and its caveat. Unticked, a row keeps the words Broad and caveat " +
                            "beside its title. Remembered in this browser; a row's arrow opens or folds that row alone." },
          tick, ' Show reasons')),
    ...(rows.length ? rows : [el('p', { class: 'muted' }, 'No ranked pivot applies to this event.')]),
    ...[notOffered, plain].filter(Boolean),
    el('p', { class: 'pv-foot muted' }, "Ranked by the fixed guidance table. Counts are case-wide, not the View's."));
  tick.addEventListener('change', () => {   // the tick sets every row, so the rows' own choices go
    ctx.open = tick.checked;
    keepReasons(ctx.open);
    overrides.clear();
    section.classList.toggle('reasons-folded', !ctx.open);
    ctx.states.forEach(syncFold);
  });
  return section;
}

// A pivot the kind doesn't rank, as a link with no count. A window carries the case's size, which the box beside it edits.
function plainLink(p, ctx) {
  if (p.pivot === 'window') {
    const box = el('input', { type: 'number', min: '1', max: '3600', value: String(p.seconds), class: 'pv-seconds',
                              'aria-label': 'Window in seconds', title: "Time window in seconds, 1 to 3,600. Saved for this case." });
    box.addEventListener('change', async () => {
      const seconds = await saveWindow({ window: { basis: 'case' } }, Number(box.value));
      if (seconds == null) box.value = String(p.seconds); else p.seconds = seconds;
    });
    return [el('button', { type: 'button', class: 'linklike pv-plain-link', 'data-pivot': 'window',
                           title: 'Events on this host within the time window of the case',
                           onclick: () => ctx.act.run({ pivot: 'window', label: p.label, seconds: Number(box.value) || p.seconds }, {}) },
                windowLabel(p.label)), box, ' s'];
  }
  const label = p.pivot === 'connection' ? `${p.label} ${p.value} within ±${p.seconds} s` : `${p.label} ${p.value}`;
  const row = { pivot: p.pivot, label: p.label, ip: p.pivot === 'addr' ? p.value : '', seconds: p.seconds };
  return [el('button', { type: 'button', class: 'linklike pv-plain-link', 'data-pivot': p.pivot, 'data-value': p.value,
                         title: `${p.label}: ${p.value}`, onclick: () => ctx.act.run(row, {}) }, label)];
}

function pivotRow(row, ctx) {
  const id = `pv${ctx.mine}-${row.n}`;   // the ids the row's arrow controls
  const ui = {
    count: el('div', { class: 'pv-n muted' }, row.count ? 'counting…' : ''),
    sources: el('div', { class: 'pv-sources' }),
    flags: el('div', { class: 'pv-flags', id: `${id}-flags` }),
    caveat: el('div', { class: 'pv-caveat muted', id: `${id}-caveat` }),
    empty: el('div', { class: 'pv-empty muted' }),
    short: el('span', { class: 'pv-short' }),   // "Broad" and "caveat", which a folded row keeps beside its title
    toggle: el('button', { type: 'button', class: 'linklike pv-tw', 'aria-controls': `${id}-reason ${id}-flags ${id}-caveat` }),
  };
  const state = { row, ui, ctx, count: null, broad: false };
  setCaveat(state, row.caveat);
  renderFlags(state);
  const title = el('div', { class: 'pv-title' });
  state.title = title;
  drawTitle(state);
  const node = el('div', { class: 'pv', 'data-pivot': row.pivot, 'data-key': row.key },
    el('span', { class: 'pv-rank' }, String(row.n)),
    el('div', { class: 'pv-main' }, title, el('div', { class: 'pv-reason', id: `${id}-reason`, ...(row.sources ? { title: `Sources: ${row.sources}` } : {}) },
                                              row.reason),
       ui.flags, ui.caveat, ui.empty),
    el('div', { class: 'pv-side' }, ui.count, ui.toggle),
    ui.sources);   // under the row's text and count, across its width
  state.node = node;
  ui.toggle.addEventListener('click', () => {
    const key = foldKey(state);
    const folded = isFolded(state);
    // A row that differs from the section is an override; one set back to the section's own state is not
    if ((folded ? 'unfolded' : 'folded') === (ctx.open ? 'unfolded' : 'folded')) overrides.delete(key);
    else overrides.set(key, folded ? 'unfolded' : 'folded');
    syncFold(state);
  });
  ctx.states.push(state);
  syncFold(state);
  if (row.count) askCount(state);
  return node;
}

const foldKey = ({ ctx, row }) => `${ctx.uid}\n${row.key}`;
const isFolded = (state) => (overrides.get(foldKey(state)) ?? (state.ctx.open ? 'unfolded' : 'folded')) === 'folded';

// The row's fold: its class against the section's state, and its arrow
function syncFold(state) {
  const { node, ui } = state;
  const own = overrides.get(foldKey(state));
  node.classList.toggle('folded', own === 'folded');
  node.classList.toggle('unfolded', own === 'unfolded');
  const folded = isFolded(state);
  ui.toggle.textContent = folded ? '▸' : '▾';
  ui.toggle.title = folded ? 'Why this pivot, and its caveat' : 'Fold the reason';
  ui.toggle.setAttribute('aria-expanded', String(!folded));
}

// The title line: the pivot, then the words a folded row keeps. The window's edit draws it again.
function drawTitle(state) { state.title.replaceChildren(...titleNodes(state), state.ui.short); }

// The words a folded row keeps beside its title: Broad when a flag begins "Broad:", and caveat when the row has one
function renderShort(state) {
  const { ui } = state;
  ui.short.replaceChildren(...[state.broad ? el('span', { class: 'br' }, 'Broad') : null,
                               ui.caveat.textContent ? el('span', { class: 'cv' }, 'caveat') : null].filter(Boolean));
}

// A caveat's text, led by the word "Caveat:". An empty text leaves the div empty, which hides it.
function setCaveat(state, text) {
  state.ui.caveat.replaceChildren(...(text ? [el('strong', {}, 'Caveat:'), ` ${text}`] : []));
  renderShort(state);
}

// The row's title: the pivot as a button, with its value, and for a window its size, which the analyst edits.
function titleNodes(state) {
  const { row, ctx } = state;
  if (row.pivot === 'window') {
    const win = row.window;
    const box = el('input', { type: 'number', min: '1', max: '3600', value: String(win.seconds), class: 'pv-seconds',
                              'aria-label': 'Window in seconds', title: 'Time window in seconds, 1 to 3,600. Saved for this case.' });
    box.addEventListener('change', async () => {
      const seconds = await ctx.act.editWindow(row, Number(box.value));
      if (seconds == null) { box.value = String(row.seconds); return; }
      row.seconds = seconds;
      row.window.seconds = seconds;
      row.window.edited = seconds !== row.window.default;
      drawTitle(state);
      askCount(state);
    });
    const basis = win.basis === 'inference'
      ? el('span', { class: 'pv-basis', title: "The guidance table infers this size from ATT&CK's examples; no source about the artifact " +
                                               'gives one. Change it to suit this case.' }, 'inference')
      : win.basis === 'source'
        ? el('span', { class: 'pv-basis', title: "This size comes from a source about the artifact, named in the hover on the row's reason." }, 'sourced')
        : el('span', { class: 'pv-basis', title: "No size of its own for this kind: the case's time window." }, 'case window');
    const reset = win.edited && win.basis !== 'case'
      ? [el('button', { type: 'button', title: `Back to ${win.default} s`,
                        onclick: async () => { box.value = String(win.default); box.dispatchEvent(new Event('change')); } }, 'reset')] : [];
    return [el('button', { type: 'button', class: 'linklike pv-go', onclick: () => ctx.act.run(row, { rank: row.n }) }, windowLabel(row.label)),
            box, ' s ', basis, ...reset];
  }
  const go = row.pivot === 'search' && row.hint
    ? () => ctx.act.search('', row.hint)
    : () => (row.pivot === 'search' ? ctx.act.search(row.term) : ctx.act.run(row, { rank: row.n }));
  const nodes = [el('button', { type: 'button', class: 'linklike pv-go',
                                title: row.pivot === 'search' ? `Search ${row.term || row.hint}` : row.warn || '', onclick: go }, row.label)];
  if (row.value) nodes.push(' ', el('code', { class: 'pv-value' }, row.value));
  // Which end of the connection the address is: the end that is a collected host's, or the one outside the case
  if (row.end === 'internal') nodes.push(' ', el('span', { class: 'muted pv-end' }, `the internal end${row.end_host ? `, ${row.end_host}` : ''}`));
  if (row.end === 'external') nodes.push(' ', el('span', { class: 'muted pv-end', title: "An address that is not any collected host's" }, 'the outside end'));
  if (row.hint) nodes.push(' ', el('span', { class: 'muted' }, row.hint));
  if (row.pivot === 'connection') nodes.push(' ', el('span', { class: 'pv-basis', title: 'Bounded to the case time window around this event; ' +
    'the list has the case-wide list one click away' }, `within ±${row.seconds} s`));
  return nodes;
}

// Why a row is broad: one of the table's broad rules fits its value (known before the count), or its count passed the
// list's limit.
function renderFlags(state) {
  const { row, ui, ctx, count } = state;
  const texts = [...row.broad];
  if (count != null && count > ctx.g.limit) {   // the window row's text points to its breakdown
    texts.push((row.pivot === 'window' ? ctx.g.over_limit_window_text : ctx.g.over_limit_text).replace('{count}', NUMBER(count)));
  }
  ui.flags.replaceChildren(...texts.map((t) => el('div', { class: 'pv-broad' }, el('strong', {}, t.startsWith('Broad:') ? 'Broad:' : 'Note:'),
                                                  ` ${t.replace(/^Broad: /, '')}`)));
  state.broad = texts.some((t) => t.startsWith('Broad:'));
  renderShort(state);
}

function showCaveat(state, res) {
  const check = state.row.caveat_check;
  if (check && check.check === 'short_path' && res.resolved) setCaveat(state, res.resolved);   // what the MFT says it is
}

// A row's count, and then its sources: the window's with the count, the others' once the count passes the limit.
async function askCount(state) {
  const { row, ctx, ui } = state;
  const { uid, at, mine, signal, g } = ctx;
  if (state.pending) state.pending.abort();
  const own = new AbortController();   // the row's own, so a new window size can end the count of the old one
  state.pending = own;
  signal.addEventListener('abort', () => own.abort(), { once: true });   // the next Event page ends them all
  const wantSources = row.breakdown === 'always';
  const ask = (breakdown) => api(`/api/pivot_count?${rowQuery(uid, at, row, {
    breakdown: breakdown ? 1 : '', check: !breakdown && row.caveat_check ? row.caveat_check.check : '' })}`, { signal: own.signal });
  ui.count.textContent = 'counting…';
  ui.count.className = 'pv-n muted';
  try {
    const res = await ask(wantSources);
    if (mine !== turn || state.pending !== own) return;
    state.count = res.count;
    ui.count.className = 'pv-n';
    ui.count.replaceChildren(el('strong', {}, eventsText(res.count)));
    renderFlags(state);
    showCaveat(state, res);
    renderSources(state, res);
    // The count of a row alone, which has the event itself: nothing else of the kind. A window or a fixed name (the log
    // clear's wevtutil.exe) never matches the event itself, so one record there is another event.
    const alone = row.pivot === 'window' || row.name ? res.count === 0 : res.count <= 1;
    ui.empty.textContent = alone && row.empty.length ? row.empty.join(' ') : '';
    if (!wantSources && res.count > g.limit) {
      const more = await ask(true);
      if (mine !== turn || state.pending !== own) return;
      renderSources(state, more);
    }
  } catch (err) {
    if (err.name === 'AbortError' || mine !== turn || state.pending !== own) return;
    ui.count.className = 'pv-n muted';
    ui.count.textContent = row.count ? 'could not count' : '';
    ui.count.title = err.message;
  }
}

// A row's breakdown: each source is a count in blue that opens the row's list narrowed to it, with the same
// total. A search row can only ask for a source as field terms, which cannot say an empty value or hold a quote, so such
// an entry is information. The sources past the largest few are text: they open only from the row's own list.
const SOURCE_FIELDS = ['artifact', 'channel', 'code', 'logon_type'];   // search's fields for queries.SOURCE_PARTS

function sourceTerm(row, s) {
  const terms = [];
  for (const [i, value] of s.source.entries()) {
    const field = SOURCE_FIELDS[i].replace('_', ' ');
    if (!value) return { why: `This source has no ${field}, which a search can't ask for; open it from the row's own list` };
    if (value.includes('"')) return { why: `This source's ${field} holds a quote, which a search can't take` };
    terms.push(`${SOURCE_FIELDS[i]}:${/\s/.test(value) || value.startsWith('-') ? `"${value}"` : value}`);
  }
  return { term: `${row.term} ${terms.join(' ')}` };
}

function sourceEntry(s, row, ctx) {
  const text = `${s.label} ${NUMBER(s.count)}`;
  const title = `List the ${eventsText(s.count)} of ${s.label} ${row.pivot === 'window' ? `within ±${row.seconds} s` : 'in this row'}`;
  if (row.pivot === 'search') {
    const { term, why } = sourceTerm(row, s);
    if (why) return el('span', { class: 'muted pv-source-info', title: why }, text);
    return el('button', { type: 'button', class: 'linklike pv-source', title, 'data-source': s.label, onclick: () => ctx.act.search(term) }, text);
  }
  return el('button', { type: 'button', class: 'linklike pv-source', title, 'data-source': s.label,
                        onclick: () => ctx.act.run(row, { source: JSON.stringify(s.source), sourceLabel: s.label, rank: row.n }) }, text);
}

function renderSources(state, res) {
  const { row, ctx, ui } = state;
  const list = res.sources || [];
  if (!list.length) { ui.sources.replaceChildren(); return; }
  const parts = list.flatMap((s, i) => [...(i ? [' · '] : []), sourceEntry(s, row, ctx)]);
  if (res.more && res.more.sources) {
    parts.push(' · ', el('span', { class: 'pv-more',
      title: `Sources past the ${list.length} largest: ${res.more.sources} more, ${eventsText(res.more.count)}. They open only from this row's own list.` },
      `+${plural(res.more.sources, 'more source')} (${eventsText(res.more.count)})`));
  }
  ui.sources.replaceChildren(...parts);
}

// The window row's edit, through the case's settings: a kind with a size of its own saves it under pivot_windows, one
// without saves the case's window, as the box beside Find related always did. Returns the size saved, or null.
export async function saveWindow(row, seconds) {
  if (!Number.isInteger(seconds) || seconds < 1 || seconds > 3600) { setStatus('A time window is 1 to 3,600 seconds'); return null; }
  try {
    if (row.window.basis === 'case') {
      await post('/api/setting', { name: 'time_window_seconds', value: seconds });
      S.meta.time_window_seconds = seconds;
    } else {
      const res = await post('/api/setting', { name: 'pivot_windows', value: { [row.window.kind]: seconds === row.window.default ? null : seconds } });
      S.meta.pivot_windows = res.value;
    }
    return seconds;
  } catch (err) { setStatus(err.message); return null; }
}
