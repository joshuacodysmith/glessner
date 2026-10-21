export const ROW_H = 20;
export const LABEL_W = 260;           // default lane label width; the analyst can drag it
export const LABELS_MIN_PX = 140;
export const LABELS_KEY = 'glessner.labelWidth';   // per-browser layout preference
// Browser preferences saved before the rename under triage-workbench.*: each is copied once to its glessner.*
// key when that key has no value yet, and the old key is left for a build from before the rename. The Details height is
// not among them: DETAILS_KEY stores it as a share of the stage, and the old key's pixel height, often 240 px, would
// come back with a copy.
const RENAMED_KEYS = ['labelWidth', 'rawFieldsOpen', 'legendOpen', 'quickActionsHidden', 'fadePivotResults'];
export function adoptOldPreferences(store) {
  for (const k of RENAMED_KEYS) {
    const old = store.getItem(`triage-workbench.${k}`);
    if (old !== null && store.getItem(`glessner.${k}`) === null) store.setItem(`glessner.${k}`, old);
  }
}
try { adoptOldPreferences(localStorage); } catch (_) { /* storage blocked */ }
export const DRAG_THRESHOLD_PX = 4;
export const HIT_PX = 3;              // a tick this near the pointer is under it: the hit test prefers it, and a pile lists it
// The wheel zooms by how far it moved: this much travel doubles or halves the window, so a mouse
// wheel's notch, 100 px in Edge, zooms by √2, and one wheel event by at most WHEEL_MAX_PX of travel. WHEEL_UNIT_PX
// turns each deltaMode into pixels: pixels, lines (three to a notch), and pages.
export const WHEEL_PX_PER_DOUBLING = 200;
export const WHEEL_MAX_PX = 300;
export const WHEEL_UNIT_PX = [1, 100 / 3, 300];
export const VIEW_ANIM_MS = 450;      // length of an animated window change
export const CELL_ZOOM_SHARE = 0.25;  // a clicked density bar grows to this share of the timeline width
export const DETAILS_MIN_PX = 80;
export const TIMELINE_MIN_PX = 160;   // the time axis plus about six lanes
// Per-browser layout preferences. The Details panel opens at two-thirds of the stage, and a
// height the analyst sets is kept as its share of the stage, so the split holds when the window changes size. The older
// keys held pixels, often the 240 px that a double-click wrote or a half-stage height. Each is removed once and never
// read.
export const DETAILS_SHARE = 2 / 3;
export const DETAILS_KEY = 'glessner.detailsShare';
export const OLD_DETAILS_KEYS = ['glessner.detailsHeight', 'glessner.detailsHeight2'];
export const LANE_FOLDS_KEY = 'glessner.laneFolds';   // per-browser: the lane groups opened or folded, by case and preset
export const LANE_FOLDS_CASES = 20;                    // cases that key remembers: the ones used last
export const LISTED_EVENTS = 500;     // selected events the verdict zone lists, as the server's LISTED_EVENTS
export const MARKS = ['Malicious', 'Suspicious', 'Authorized', 'Unreviewed'];   // analyst marks
// Lane order: analyst marks and pending suggestions, most severe first.
export const MARK_ORDER = ['Malicious', 'Suspicious', 'Suggested: malicious', 'Suggested: suspicious', 'Authorized',
                    'Suggested: authorized', 'Unreviewed'];
export const RULE_TEMPLATE = `id: my-rule
description: What this rule recognizes, and why
suggest: authorized
when:
  all:
    - {field: account, equals: 'DOMAIN\\svc_backup'}
    - {field: host, in: [BACKUP01]}
`;
export const MARK_VALUE = { Unreviewed: 'unreviewed', Authorized: 'authorized', Suspicious: 'suspicious', Malicious: 'malicious' };
export const KEY_LABEL = { mark: 'Mark', role: 'Role', host: 'Host', user: 'User', tool: 'Tool', artifact: 'Artifact', tactic: 'Tactic' };
export const ROLES = ['Domain controllers', 'Servers', 'Workstations', 'Network devices'];
export const OUTSIDE_GROUP = '__outside__';
export const STEPS_MS = [1e3, 5e3, 15e3, 3e4, 6e4, 3e5, 9e5, 18e5, 36e5, 108e5, 216e5, 432e5, 864e5, 6048e5,
                  2592e6, 7776e6, 31536e6, 157680e6];
// One-line hover hints for the Case panel's and the Timeline toolbar's controls, by element ID,
// kept here so each is written once. A control whose hover text adds live detail, such as Fit case's strays or the
// counts on To investigate, starts it with its hint.
export const HINTS = {
  tabOverview: 'Overview: where to start, your progress, what the case holds, its gaps, and its integrity.',
  tabTimeline: "Timeline: the case's events in lanes, with the Details panel below.",
  investigateButton: 'To investigate: your Malicious and Suspicious events with what is unreviewed around them, and pending suggestions.',
  tabFindings: 'Findings: your findings, each with its events and what they do not prove, and the exports beside them.',
  tabAudit: 'Audit trail: every journal entry in plain words, with undo for an accident.',
  searchHelp: 'Search help: the syntax, the fields, and examples to run.',
  caseMenuButton: 'Case: hosts, tools, imports, rules, exports, the audit trail, and other cases.',
  hostsButton: "Hosts: each host's role, names, IPs, OS, and clock, and what needs review.",
  toolsButton: 'Tools: run the forensic tools and load tool output found in the evidence.',
  importButton: 'Import: read text logs that no tool reads, such as firewall logs, by a mapping.',
  rulesButton: 'Rules: the suggestion rules, and an editor to add or change them.',
  exportButton: 'Export: write the report, the marked events, the window, the indicators, or the audit trail, from the Findings page.',
  auditButton: 'Audit trail: every journal entry in plain words, with undo for an accident.',
  casesButton: 'Cases: recent cases, a new case, or a copy.',
  lanesLabel: 'Lanes: how the timeline groups its rows, such as by mark, then role, then host.',
  foldAll: 'Open all: open every lane group. While any group is open it reads Fold all, which folds the first-level groups again.',
  fit: 'Fit case: show the whole case, less far-off strays.',
  filtersButton: 'Sources: show or hide hosts, evidence types, files, and the channels inside a file. Hidden events still count for pivots and search.',
  viewButton: 'View: show only events with chosen marks or values pinned from events. Hidden events still count for pivots, links, and search.',
  linksLabel: "Logon links: draw an arrow from each logon's source to the host that recorded it.",
  machineLabel: 'Hide machine accounts ($): leave out the logon links of accounts ending in $, mostly routine. Their events stay.',
  clockRecorded: "Recorded: each host's times as its own clock recorded them. Sets back the offsets this switch set; typed ones stay.",
  clockAligned: 'Aligned to capture: give each host measured against the capture its suggested offset, journaled. Evidence times never change.',
  clockPartly: "Some measured hosts are aligned to the capture and some aren't. The Hosts panel shows each one.",
  addZone: "+ zone: add an axis under the UTC axis in another time zone, such as a host's own.",
  legendButton: 'Legend: what each mark on the timeline means. Press L to show or hide it.',
};

export const S = {
  meta: null, groupby: ['mark', 'role', 'host'], lanes: [], laneSet: new Set(), tree: null,
  rows: [], rowIndex: new Map(), view: { start: 0, end: 1 }, width: 600,
  foldChoices: new Map(),   // lane groups the analyst opened (true) or folded (false), by node ID; the rest fold by depth
  laneNames: {},   // lane labels by group-by key and lane key, where they differ, such as a user lane's spelling
  data: null, selected: new Set(), focus: null, related: new Set(), index: [], linkSegs: [],
  windowLinks: [],   // time-window relation: [{uid, gap_s}] around S.focus, drawn dashed
  timer: null, drag: null, linkNote: '', pivotResult: null,
  linksDrawn: 0, linksFolded: 0,   // the last draw's logon links drawn, and those whose ends fell in one folded group
  trail: [], trailAt: -1, trailVia: false,   // the pivot trail of the tab (trail.js), the step on screen, and how the next Event page
  // opens: from a pivot's list (true), by Back ('back'), or neither (false)
  anim: null,   // the window animation in progress: { view, loaded, timer }
  page: null, back: [], goingBack: false,   // the Details panel's current page and its Back history
  filter: { only: [], hide: [], show: [] }, filterId: null,   // the view filter and its server ID; never kept across a reload
  shown: null, filterApplying: null,   // the filter's shown counts per source file, and its pending apply
  labelW: LABEL_W, labelWant: LABEL_W,
  zones: [], zoneAxes: [],   // the zone axes saved with the case, and their drawn clocks and canvases
  viewSpec: null, faded: [], markCounts: null,   // the View (marks and pinned values), faded pivot results, mark counts
  viewSuggestedTags: false,   // the View's Include suggested tags; off on every load, like the View itself
  tagCounts: null,   // events per tag, applied and suggested, for the View filter's Tactics section
  pivotChecked: new Set(),   // pivot list events ticked for marking
  sources: null, fpOpen: new Set(), fpAll: new Set(), fpQuery: '',   // the Sources panel's data, open nodes, and search
  highlight: null,   // the open search's terms, each as its pieces between stars; see setHighlight
  focusEvent: null,   // the Event page's event: { uid, host, recorded, adjusted, short, label }, kept in place when clocks are aligned
  pairLink: null, pairDrawn: null,   // the focused event's pair with the capture, and what drawPairLink drew
  tab: 'timeline', overview: null,   // the path's current step, and the Case overview as last read
  // The state line's counts: events the filter shows over the whole case; while a View and the Sources
  // are both on, those each part alone shows; and the case's machine-account logon links
  lanesShown: null, sourcesShown: null, viewShown: null, machineLinks: null,
  journal: null,   // the journal's chain as /api/case_state last gave it: broken, why it's read-only, the head
  caseChanged: null,   // why the page sends nothing more: another case is open on the server
  viewStatus: '',   // the view's notes for the status line, after the last action: links, Sources, the View, the strays
  lastAction: null,   // what the status line reports first: { text, ms }, an action's or "Window moved" (reportAction)
  shownWindow: null, windowPending: false,   // the window the drawn data is for, and whether a new window's data is still due
  // The find boxes' text by list name, for the Details page on screen (pages.listFind): setPage starts it
  // again when the page's key changes, so a redraw keeps a find and a new page starts empty
  finds: { key: null, lists: new Map() },
};
window.__timings = [];

export const $ = (id) => document.getElementById(id);

// Search terms to highlight: set by a search, used by its result list and by the Event pages
// opened from it, and cleared when another page opens. A field:value term highlights only a whole value. A term is
// kept as its pieces between the stars, each found once after the one before, as the server finds them
// (search.wildcard_span). One regular expression with .*? for each star backtracked over a repeated text when a later
// piece was missing: a*a*a*a*a*b froze the page for over 5 s on a message of 160 a's. A bounded term (a
// quoted word) is found only between word characters, where its own first and last character is one, as the server finds
// it (search.bounded_pattern): ASCII letters, digits, and underscore. The lookarounds say so; \b would count accents too.
const WORD = /[A-Za-z0-9_]/;
export function setHighlight(terms) {
  S.highlight = terms && terms.length ? terms.map((t) => {
    const parts = t.value.split('*');
    return {
      whole: t.whole,
      pieces: parts.map((part, i) => {
        let src = part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if (t.bounded && i === 0 && WORD.test(part.charAt(0))) src = `(?<![A-Za-z0-9_])${src}`;
        if (t.bounded && i === parts.length - 1 && WORD.test(part.charAt(part.length - 1))) src += '(?![A-Za-z0-9_])';
        return { length: part.length, find: new RegExp(src, 'gi'), at: new RegExp(src, 'iy') };   // anywhere, or just here
      }),
    };
  }) : null;
}

// Where a term's pieces are found in turn from `from`: [start, end] from the first piece's start to the last one's
// end, or null.
function piecesSpan(pieces, s, from) {
  let start = from, pos = from;
  for (const [i, p] of pieces.entries()) {
    p.find.lastIndex = pos;
    const m = p.find.exec(s);
    if (!m) return null;
    if (i === 0) start = m.index;
    pos = m.index + m[0].length;
  }
  return [start, pos];
}

const pieceAt = (p, s, i) => { p.at.lastIndex = i; return p.at.test(s); };

// Whether a whole value is the term: its first piece at the start, its last at the end, and the others in turn between.
function wholeMatch(pieces, s) {
  const first = pieces[0], last = pieces[pieces.length - 1];
  if (pieces.length === 1) return first.length === s.length && pieceAt(first, s, 0);
  const end = s.length - last.length;
  return end >= first.length && pieceAt(first, s, 0) && pieceAt(last, s, end)
    && piecesSpan(pieces.slice(1, -1), s.slice(0, end), first.length) !== null;
}

// Text as nodes, with the highlighted terms in <mark> elements. Text goes in as text nodes, never as HTML.
export function marked(text) {
  const s = String(text ?? '');
  if (!S.highlight || !s) return [s];
  const ranges = [];
  for (const term of S.highlight) {
    if (term.whole) {
      if (ranges.length < 100 && wholeMatch(term.pieces, s)) ranges.push([0, s.length]);
      continue;
    }
    let pos = 0, span;
    while (ranges.length < 100 && pos <= s.length && (span = piecesSpan(term.pieces, s, pos))) {
      if (span[1] > span[0]) { ranges.push(span); pos = span[1]; } else pos = span[0] + 1;
    }
  }
  if (!ranges.length) return [s];
  ranges.sort((a, b) => a[0] - b[0]);
  const out = [];
  let pos = 0;
  for (const [a, b] of ranges) {
    if (b <= pos) continue;
    const from = Math.max(a, pos);
    if (from > pos) out.push(s.slice(pos, from));
    const mark = document.createElement('mark');
    mark.textContent = s.slice(from, b);
    out.push(mark);
    pos = b;
  }
  if (pos < s.length) out.push(s.slice(pos));
  return out;
}
export const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (k === 'style') node.style.cssText = v;   // the CSP blocks style attributes, not the DOM
    else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return node;
}

// The band that opens each of the Timeline's side panels: the panel's name and its head action, in the
// Timeline's cool band, staying at the top while the panel scrolls.
export const panelBand = (name, ...actions) => el('div', { class: 'band timeline panel-head' }, el('span', { class: 'name' }, name), ...actions);

// The button that opens a Timeline side panel (Sources, View, Legend) shows the pressed state while its panel is open, and
// says so to a screen reader. The pressed look is the one every toggle has.
export function setPanelButton(id, open) {
  const b = $(id);
  b.setAttribute('aria-pressed', String(open));
  b.setAttribute('aria-expanded', String(open));
}
// Sources and View share one flyout slot, so both buttons follow whichever panel is open.
export function syncPanelButtons() {
  setPanelButton('filtersButton', !$('filterPanel').hidden);
  setPanelButton('viewButton', !$('viewPanel').hidden);
}

// Every request names the case open the page shows, once /api/meta has given its ID, and the server refuses one that
// names another: a tab still showing one case had journaled marks, notes, and settings into a case a second tab opened
// on the same server. The page then says so, offers a reload, and sends nothing more. A tab left
// from an earlier run of `serve` reaches the new run's server on the same port and is refused the same
// way, without the reload: its session cookie is the old run's, and the new link is the way in.
export async function api(path, opts = {}) {
  if (S.caseChanged) throw new Error(S.caseChanged);
  const caseId = S.meta && S.meta.case_id;
  const res = await fetch(path, caseId ? { ...opts, headers: { ...opts.headers, 'X-Glessner-Case': caseId } } : opts);
  // An answer that isn't JSON, such as a 404's text, is its text, not a JSON parse error
  const body = (res.headers.get('Content-Type') || '').startsWith('application/json') ? await res.json()
    : { error: (await res.text()).trim() || `HTTP ${res.status}` };
  if (res.status === 409 && body.case_changed) caseChanged(body.error, true);
  if (res.status === 403 && body.stale_session) caseChanged(body.error, false);
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

function caseChanged(message, reload) {
  if (S.caseChanged) return;
  S.caseChanged = message;
  document.body.prepend(el('div', { id: 'caseChanged', class: 'case-changed', role: 'alert' }, message,
    ...(reload ? [' ', el('button', { type: 'button', onclick: () => location.reload() }, 'Reload')] : [])));
  setStatus(message);
}
export const post = (path, body) => api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

// An event without a time says so: rules match such events, so an accept can list one, and a null time would read as
// 1970-01-01.
export function fmtUs(us) {
  if (us == null) return 'No time recorded';
  const iso = new Date(Math.floor(us / 1000)).toISOString().slice(0, 19).replace('T', ' ');
  return `${iso}.${String(((us % 1e6) + 1e6) % 1e6).padStart(6, '0')}`;
}
export const fmtMs = (ms) => new Date(ms).toISOString().replace('T', ' ').replace('Z', '');
// The one formatter for a gap in seconds: a list's offset cell, a window link's label, and a reach
// line. Under a second it is whole milliseconds, under a minute whole seconds, and from a minute the largest unit that
// fits and the next one down (years of 365 days, days, hours, minutes, seconds), both cut toward zero, the second left off
// when it is zero: "+412 ms", "+4 s", "+1 min 2 s", "-2 h 21 min", "-9 y 159 d". `reach` writes "±" for the sign. Null is
// empty and 0 is "0 s". The sign is a hyphen-minus, so the text copies and searches.
const GAP_UNITS = [['y', 31536000], ['d', 86400], ['h', 3600], ['min', 60], ['s', 1]];
export function fmtGap(s, { reach = false } = {}) {
  if (s == null) return '';
  if (s === 0) return '0 s';
  const sign = reach ? '±' : s < 0 ? '-' : '+';
  const a = Math.abs(s);
  if (a < 1) return `${sign}${Math.floor(a * 1000 + 1e-6)} ms`;   // the server rounds to milliseconds; the nudge keeps 0.29 s from reading 289
  const i = GAP_UNITS.findIndex(([, size]) => a >= size);
  const [name, size] = GAP_UNITS[i];
  const first = Math.floor(a / size);
  if (name === 's') return `${sign}${first} s`;
  const [next, nextSize] = GAP_UNITS[i + 1];
  const second = Math.floor((a - first * size) / nextSize);
  return `${sign}${first} ${name}${second ? ` ${second} ${next}` : ''}`;
}
// The exact gap for a hover: "+4.120 s", "-8,510.000 s", and "this event" for 0.
export function gapTitle(s) {
  if (s == null) return '';
  if (s === 0) return 'this event';
  return `${s < 0 ? '-' : '+'}${Math.abs(s).toLocaleString('en-US', { minimumFractionDigits: 3, maximumFractionDigits: 3 })} s`;
}
// The window a timeline export covers, as the Findings page's window card names it.
export const windowText = (view = S.view) => `${fmtMs(view.start)} to ${fmtMs(view.end)} UTC`;
export const setStatus = (text) => { const s = $('status'); s.textContent = text; s.title = text; };   // its hover, when cut short
// The status line: the last action and the server's time for it, then the view's notes after " | ".
// An action reports itself after its redraw; a redraw of the same window keeps the last action, and a new window is itself
// the last action, "Window moved" (data.showData). The line holds the action and the view's notes together, so a redraw
// can't take the action away. A report with no time, such as a warning at start, shows its text alone.
export function renderStatus() {
  const a = S.lastAction;
  const head = a ? (a.ms == null ? a.text : `${a.text} · ${Math.round(a.ms)} ms`) : '';
  setStatus([head, S.viewStatus].filter(Boolean).join(' | '));
}
export function reportAction(text, ms) {
  S.lastAction = { text, ms };
  renderStatus();
}
// A journal time as the page words it: "YYYY-MM-DD HH:MM UTC".
export const fmtAt = (at) => (at ? `${String(at).slice(0, 16).replace('T', ' ')} UTC` : '');

// The review state a mark string names, for the badge: the letter and class, the word, and, for a
// pending suggestion, what it suggests. The string is the server's MARK_EXPR: a mark's label, "Suggested: X", or
// "Unreviewed". Both of the last two are U, since a suggestion is a guide and not a mark.
const BADGE = { Malicious: ['M', 'm'], Suspicious: ['S', 's'], Authorized: ['A', 'a'] };
export function markState(mark) {
  const label = String(mark ?? 'Unreviewed');
  if (label.startsWith('Suggested: ')) {
    const word = label.slice(11);
    return { letter: 'U', cls: 'u', word: 'Unreviewed', suggested: word.charAt(0).toUpperCase() + word.slice(1).toLowerCase() };
  }
  const [letter, cls] = BADGE[label] || ['U', 'u'];
  return { letter, cls, word: BADGE[label] ? label : 'Unreviewed', suggested: null };
}

// The review-state badge: one letter in a small box, U hollow, the others filled. `e` is a listed event, or anything with
// a `mark`, and `mark_who` and `mark_at` where the server gave them, and `suggest_source` for a pending suggestion's
// source. The hover and the accessible name say the word, and who marked it and when. The badge stands for the word and
// never sits beside it: where the state is spelled out, there is no badge.
export function markBadge(e) {
  const st = markState(e.mark);
  const badge = el('span', { class: `badge ${st.cls}` }, st.letter);
  const said = st.suggested
    ? `${st.word}, with a pending ${st.suggested} suggestion${e.suggest_source ? ` from ${e.suggest_source}` : ''}`
    : e.mark_who ? `${st.word}, marked by ${e.mark_who}${e.mark_at ? `, ${fmtAt(e.mark_at)}` : ''}` : st.word;
  badge.setAttribute('role', 'img');
  badge.setAttribute('aria-label', said);
  badge.title = said;
  return badge;
}

// Text cut to `n` characters with an ellipsis, for the menu's and the tooltip's first lines
export const cut = (text, n) => (text.length > n ? `${text.slice(0, n)}…` : text);
// A count and its noun, singular for 1: "1 event", "2 events".
export const plural = (n, word, many = `${word}s`) => `${n.toLocaleString()} ${n === 1 ? word : many}`;
// A list row's event code, before its message. An event log message starts with its event ID, so the code isn't
// written twice, as "4624 4624 Successful logon".
export const codePrefix = (e) => (e.code && !String(e.msg ?? '').startsWith(`${e.code} `) ? `${e.code}  ` : '');

// Links the server skipped rather than followed in the evidence, each "path -> target", as a
// sentence to add to a note; '' for none.
export function skippedLinks(links) {
  if (!links || !links.length) return '';
  const shown = links.slice(0, 3).join('; ') + (links.length > 3 ? `; and ${links.length - 3} more` : '');
  return ` Skipped ${plural(links.length, 'link')}, not followed: ${shown}.`;
}


// Five pivots and their labels; the Hosts panel names all but Same logon session as case-wide (hosts.js CASE_WIDE)
export const PIVOTS = [['session', 'Same logon session'], ['account', 'Same account'], ['source_ip', 'Same source IP'],
                ['connection', 'Same source IP and port'], ['file', 'Same file']];
// What each pivot the server matches is called in a trail step and a list's heading, where the Event page's row gave no label
export const PIVOT_LABELS = { session: 'Same logon session', account: 'Same account', source_ip: 'Same source IP',
  connection: 'Same source IP and port', file: 'Same file', file_name: 'Same file name', addr: 'Same IP at either end',
  window: 'Same host within the window', service_name: 'Same service name', workstation: 'Same workstation', flow: 'Same flow', task_name: 'Same task name',
  rule: 'Same rule or signature', hash: 'Same hash' };
// The IP pivot at either end has a row of its own: one button per address
// the event has, source or destination, since older Sysmon records an inbound connection's remote side as the destination.
export const EITHER_END_PIVOT = ['addr', 'Same IP at either end'];
