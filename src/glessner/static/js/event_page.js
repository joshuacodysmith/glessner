import { HISTORY_LIMIT, loadHistory, retractNote } from './audit.js';
import { clockFolds, clockHover, clockNote, setPairLink } from './clock.js';
import { askSelection, CONFIRM_ABOVE, markWord } from './confirm.js';
import { $, api, codePrefix, el, fmtAt, fmtUs, LISTED_EVENTS, lookup, MARK_VALUE, markBadge, marked, MARKS, plural, post, reportAction, S, setStatus, toolName } from './core.js';
import { refreshCounts } from './counts.js';
import { fetchView } from './data.js';
import { draw } from './draw.js';
import { caveatBox, findingRow } from './findings.js';
import { followPage } from './frame.js';
import { reloadLanes } from './lanes.js';
import { addNote, listFind, pivot, renderRelated } from './pages.js';
import { pivotPanel, saveWindow } from './pivots.js';
import { groupReviewOf, reviewBar } from './review.js';
import { addToSearch, runSearch } from './search.js';
import { tagZone } from './tags.js';
import { eventLabel, eventShort, trailBar, trailEvent, trailPivot, trailText } from './trail.js';
import { addressToggle, ADDRESS_FIELDS, refreshViewCounts, viewToggle } from './view.js';
import { hostLocalText } from './zones.js';

// ---------- Event page, in the Details panel ----------

export const LOGON_TYPES = { 2: 'Interactive', 3: 'Network', 4: 'Batch', 5: 'Service', 7: 'Unlock', 8: 'NetworkCleartext',
                      9: 'NewCredentials', 10: 'RemoteInteractive', 11: 'CachedInteractive', 12: 'CachedRemoteInteractive',
                      13: 'CachedUnlock' };
// The tool's own fields worth reading for each artifact, from the event's extra data. Null means all of them:
// for EVTX, extra is the record's EventData.
export const ARTIFACT_DETAILS = {
  evtx: ['Event data', null],
  hayabusa: ['Hayabusa details', ['Details', 'MitreTactics', 'MitreTags', 'OtherTags', 'RuleFile']],
  mft: ['MFT entry', ['FileSize', 'InUse', 'IsDirectory', 'SI<FN', 'FnEqualsSi', 'uSecZeros', 'Copied', 'HasAds', 'IsAds',
                     'ZoneIdContents', 'ReparseTarget', 'EntryNumber', 'SequenceNumber', 'ParentEntryNumber']],
  prefetch: ['Prefetch', ['RunCount', 'Hash', 'Size', 'Version', 'FilesLoadedCount', 'Volume0Name', 'Volume0Serial', 'Note',
                          'ParsingError']],
  lnk: ['Shortcut (LNK)', ['LocalPath', 'NetworkPath', 'CommonPath', 'TargetIDAbsolutePath', 'Arguments', 'WorkingDirectory',
                           'RelativePath', 'FileSize', 'FileAttributes', 'DriveType', 'VolumeLabel', 'VolumeSerialNumber',
                           'TargetMFTEntryNumber', 'TargetMFTSequenceNumber', 'MachineID', 'MachineMACAddress', 'MACVendor',
                           'VolumeDroid', 'FileDroid', 'VolumeDroidBirth', 'FileDroidBirth']],
  // The MountedDevices decode's fields follow the ValueData2 they are read from
  registry: ['Registry value', ['HiveType', 'Category', 'ValueType', 'ValueData', 'ValueData2', 'DataFormat', 'DiskSignature',
                                'PartitionOffset', 'PartitionSector', 'PartitionGuid', 'DeviceBus', 'DeviceVendorProduct',
                                'DeviceInstance', 'DeviceClassGuid', 'ValueData3', 'Comment', 'Deleted']],
  shellbags: ['ShellBag', ['AbsolutePath', 'ShellType', 'Value', 'FirstInteracted', 'LastInteracted', 'LastWriteTime',
                           'CreatedOn', 'ModifiedOn', 'AccessedOn', 'HasExplored', 'MFTEntry', 'MFTSequenceNumber', 'Profile',
                           'Hive', 'BagPath', 'Slot', 'Miscellaneous']],
  amcache: ['Amcache', ['SHA1', 'FullPath', 'Name', 'ProductName', 'CompanyName', 'Version', 'FileVersionString', 'Publisher',
                        'ProgramName', 'ProgramName_0', 'ProgramVersion_1', 'VendorName_2', 'InstallDate', 'InstallDateEpoch_a',
                        'LinkDate', 'Created', 'LastModified', 'Size', 'FileSize', 'IsOsComponent', 'BinaryType', 'RootDirPath',
                        'PathsList_d', 'LnkName', 'Table']],
  jumplist: ['Jump list', ['AppIdDescription', 'AppId', 'Path', 'LocalPath', 'NetworkPath', 'TargetIDAbsolutePath', 'Arguments',
                           'InteractionCount', 'PinStatus', 'CreationTime', 'LastModified', 'TargetCreated', 'TargetModified',
                           'TargetAccessed', 'Hostname', 'MacAddress', 'EntryNumber', 'FileSize', 'VolumeLabel',
                           'VolumeSerialNumber']],
  srum: ['SRUM', ['Table', 'ExeInfo', 'ExeInfoDescription', 'UserName', 'Sid', 'BytesSent', 'BytesReceived', 'InterfaceType',
                  'ProfileName', 'ConnectStartTime', 'ConnectedTime', 'EndTime', 'DurationMs', 'ForegroundBytesRead',
                  'ForegroundBytesWritten', 'BackgroundBytesRead', 'BackgroundBytesWritten', 'Timestamp']],
  recycle_bin: ['Recycle Bin', ['FileName', 'FileSize', 'DeletedOn', 'FileType', 'SID']],
  // Autoruns' own column names; Time is as written, in local time
  autoruns: ['Autoruns entry', ['Category', 'Entry', 'Entry Location', 'Enabled', 'Profile', 'Description', 'Company', 'Signer',
                                'Version', 'Image Path', 'Launch String', 'Time', 'LocationLastWritten', 'MD5', 'SHA-1',
                                'SHA-256', 'PESHA-1', 'PESHA-256', 'IMP']],
};
export const MACB = { M: 'modified', A: 'accessed', C: 'MFT entry changed', B: 'created' };
export const RAW_OPEN_KEY = 'glessner.rawFieldsOpen';   // per-browser: whether Raw fields starts open
export const RECORD_OPEN_KEY = 'glessner.recordSourceOpen';   // and Record and source
export const HISTORY_OPEN_KEY = 'glessner.historyOpen';   // and History
// Computed or structured parts of the event response; the rest are event columns, listed under Raw fields. The
// account key and the hash list are columns the load computes from others, so Raw fields leaves them out too.
// Shown elsewhere on the page; tags and tag_suggestions are lists of objects, which Raw fields would print as
// "[object Object]".
export const NOT_RAW = new Set(['extra', 'hits', 'mark', 'notes', 'suggestions', 'evidence_sha256', 'offset_us', 'adjusted_ts_us',
                                'pair', 'clock', 'tags', 'tag_suggestions', 'split', 'provenance', 'pivots', 'id_changed',
                                'id_also_named', 'unplaced', 'followup', 'rejection_notes',
                                'account_key', 'hashes', 'caveat', 'findings', 'host_clock']);

// Counts the pages asked of the Details panel, so only the latest draws. A page that draws when its request answers,
// such as an Event page, a search, or To investigate, claims the panel when asked; claimDetails returns a check that no
// later page has claimed it since. setPage claims it for any other page it draws, such as Export. A shift-click on
// stacked events keeps the focus, and the focused event's page would replace their list a moment later; a search that
// answers late would replace the Event page opened after it, and To investigate, Rules, or the audit trail opened after it.
// The check of a page's redraw after an action (settleRedraw) also fails while a question is open on the page, which the
// redraw would take away; the page then notes the claims again and owes the redraw, which runs once the question has left.
let detailsTurn = 0;
export const claimDetails = () => {
  const turn = ++detailsTurn;
  return () => {
    if (turn !== detailsTurn) return false;
    if (turn !== settling || !asking()) return true;
    drawn.claims = turn;
    drawn.held = true;
    return false;
  };
};
// The claims made so far, read without claiming: a page that has drawn can tell later whether one was asked for since.
export const detailsClaims = () => detailsTurn;
// Whether the panel still shows the page with this key. A page's action, such as Accept all or Remove, redraws the page
// when it answers, and the answer would replace whatever page the analyst asked for meanwhile.
export const showingPage = (key) => $('details').dataset.key === key;

// An action on a page, such as Accept all, Remove, or a note, redraws that page when the server answers, so the page shows
// the change. A page asked for meanwhile keeps the panel: the redraw waits for no page asked for since the claims the
// page on screen last noted, when it drew and when an action on it started. A page left and opened again while the
// action was out redraws once more, when the action answers or when it draws, if its read went out before the answer.
// An action can redraw only the part of the page it changed, such as the list a tag came from. When the page can't draw
// that part as the action answers, it draws it when it next draws, whenever its read went out, since the page's read may
// not read the part again: an Event page draws its pivot's list from the rows it kept.
// A question open on the page, such as a second group's Accept all, holds the redraw, which would take the question
// away. The page redraws once the question has left it, however it left: answered, canceled, or drawn over by the page
// itself, as a tick in a list draws the list again. A redraw whose read is out when a question opens is held as its read
// answers. A refusal in the question's place asks nothing and holds nothing.
let answers = 0;                  // actions answered, on any page
const answeredOn = new Map();     // page key: the number of the last action answered on that page that redraws all of it
const owedParts = new Map();      // page key: how to draw the part of the page an action changed, until the page can
// The page on screen, as it last noted itself. `held` says a question held the read of its redraw.
let drawn = { key: null, read: 0, claims: 0, redraw: null, held: false };
let settling = 0;                 // the claim of the last redraw that followed an action

// Whether a question (confirm.js's askConfirm) is open on the page in the Details panel. A refusal in its place is an
// alert, not a group.
const asking = () => $('detailsBody').querySelector('.confirm-block[role="group"]') !== null;
// Whether the page on screen, with this key, is owed a redraw of all of it
const owedWhole = (key) => drawn.held || (answeredOn.get(key) || 0) > drawn.read;
const owes = (key) => owedWhole(key) || owedParts.has(key);
new MutationObserver(() => { if (drawn.key && owes(drawn.key) && !asking()) settlePage(drawn.key); })
  .observe($('detailsBody'), { childList: true, subtree: true });

// Called as a page's read goes out; what it returns is called once the page has drawn, with the page's key and how to
// draw it again with the same options.
export function pageRead() {
  const read = answers;   // the actions answered before the read, which it is sure to show
  return (key, redraw) => {
    drawn = { key, read, claims: detailsClaims(), redraw, held: false };
    settlePage(key);
  };
}

// Called as an action on the page with this key goes out; what it returns is called once the server has answered, and
// passes `redraw` to pageAnswered.
export function pageAction(key) {
  if (drawn.key === key && showingPage(key)) drawn.claims = detailsClaims();
  return (redraw = true) => pageAnswered(key, redraw);
}

// Note that an action has answered for the page with this key, as what pageAction returns does, for a page the action
// didn't note as it went out, such as the Event page of an event opened while a host change was out. It doesn't note the
// page's claims, so a page asked for since the page drew keeps the panel. Redraws the page, unless `redraw` is false,
// which leaves the redraw to the caller (settleRedraw); a function draws the part the action changed in place of the
// whole page, such as the list a tag came from. Returns whether the page can draw now: the panel shows it, no page was
// asked for since, and no question is open on it. One still loading redraws as it draws, and one under a question once
// the question has left.
export function pageAnswered(key, redraw = true) {
  answers += 1;
  if (typeof redraw === 'function') owedParts.set(key, redraw);
  else answeredOn.set(key, answers);
  return settlePage(key, redraw !== false);
}

// Run `redraw`, a page's redraw after an action on it answered, as settlePage does and as a caller does when what
// pageAction returned, given false, says the page can draw. A question opened before the redraw's read answers holds the
// redraw. Returns what `redraw` returns.
export function settleRedraw(redraw) {
  const before = detailsTurn;
  const result = redraw();
  if (detailsTurn !== before) settling = detailsTurn;   // the redraw's read claimed the panel as it went out
  return result;
}

// Called when the page on screen has claimed the panel to draw part of itself again from its earlier read, as the Import
// page's preview does. The page notes the claims again, so an action's redraw still reaches it, and redraws now if an
// action answered meanwhile.
export function keepPage(key) {
  if (drawn.key !== key || !showingPage(key)) return;
  drawn.claims = detailsClaims();
  settlePage(key);
}

// Draw what the page with this key is owed, when the panel shows it, no page was asked for since, and no question is open
// on it: the whole page, unless `whole` is false, which leaves that to the caller, and the parts actions changed.
// Returns whether the page could draw.
function settlePage(key, whole = true) {
  if (drawn.key !== key || !showingPage(key) || detailsClaims() !== drawn.claims) return false;
  if (asking() && owes(key)) return false;
  const redraw = owedWhole(key);
  drawn.held = false;
  if (!whole) return true;
  const part = owedParts.get(key);
  owedParts.delete(key);
  if (redraw) settleRedraw(drawn.redraw);
  if (part) settleRedraw(part);
  return true;
}

// Show one page in the Details panel. The panel is a band over one scroller, #detailsBody: the page goes
// into the body, and the band names the page, with Back and the trail. The scroll position resets only when the page or
// event changes. A page that says how to reopen itself joins the Back history when another page replaces it, except a
// page of the same `group`, such as another event of one selection list: the pages of a group take one place in the
// history, the last one shown. A redraw on the page's own key joins it too when it `leaves` the page behind, as a new
// selection leaves the page of a selection list's event; `leaves` is then that page's title in Back. A page redrawn, as
// after a tick, keeps the claim its own request holds.
export function setPage(name, nodes, { key = name, title = '', reopen = null, group = null, leaves = null } = {}) {
  const panel = $('details'), body = $('detailsBody');
  const same = panel.dataset.key === key;
  if (!same) claimDetails();
  if (!same) S.finds = { key, lists: new Map() };   // a new page's lists start with no find
  // A new page's groups start as it draws them; the Suggestions page notes its groups under its key as it builds them
  if (S.folds.key !== key) S.folds = { key, open: new Map() };
  if (S.decided.key !== key) S.decided = { key, rows: new Map() };   // and with no rows decided
  if (S.ticks.key !== key) S.ticks = { key, groupBy: null, groups: new Map() };   // or ticked
  const top = body.scrollTop;
  const places = same ? [...body.querySelectorAll('[data-scroll]')].map((n) => [n.dataset.scroll, n.scrollTop]) : [];
  let left = null;   // the page on screen, as it joins Back
  if (S.page && !S.goingBack) {
    if (!same && !(group && S.page.group === group)) left = S.page;
    else if (same && leaves) left = { ...S.page, title: leaves };
  }
  if (left) {
    S.back.push(left);
    if (S.back.length > 20) S.back.shift();
  }
  S.goingBack = false;
  if (name !== 'event' && name !== 'search') S.highlight = null;   // search terms stay highlighted on its events only
  S.page = reopen ? { key, title, reopen, group } : null;
  bandTitle = title;
  panel.dataset.page = name;
  panel.dataset.key = key;
  followPage(name);   // the path lights the page's step, and the overview gives way to it
  body.replaceChildren(...nodes);
  body.scrollTop = same ? top : 0;
  for (const [name, y] of places) { const n = body.querySelector(`[data-scroll="${name}"]`); if (n) n.scrollTop = y; }
  renderBand();
  watchHeads();
}

let bandTitle = '';

// The Details band: the panel's name, what the page shows, Back, and the pivot trail on every page. It
// sits outside the scroller, so a pivot never scrolls the trail away.
export function renderBand() {
  const prev = S.back[S.back.length - 1];
  const trail = trailBar({ go: goToStep, save: saveTrail, current: currentStep() });
  const nodes = [el('span', { class: 'name' }, 'Details')];
  if (prev || bandTitle || trail) nodes.push(el('span', { class: 'sep', 'aria-hidden': 'true' }));
  if (prev) nodes.push(el('span', { class: 'back-bar' }, button(`‹ Back to ${prev.title}`, goBack, { class: 'linklike back' })));
  if (bandTitle) nodes.push(el('span', { class: 'title', title: bandTitle }, bandTitle));
  if (trail) nodes.push(trail);
  $('detailsBand').replaceChildren(...nodes);
}

// The step the panel shows: an Event page is the trail's step at S.trailAt, and so is a search that step ran. Any other
// page is not a step, so every step is a link there.
function currentStep() {
  const at = S.trail[S.trailAt];
  if (!at) return -1;
  const panel = $('details');
  const shown = panel.dataset.page === 'event' || (panel.dataset.page === 'search' && at.kind === 'search'
                                                    && panel.dataset.key === `search:${at.term}`);
  return shown ? S.trailAt : -1;
}

// Save trail as a note: on the event the trail started from, which may not be the one on screen. That event's page
// redraws only while the panel shows it, as after any note (pageAction).
async function saveTrail() {
  const start = S.trail[0];
  if (!start) return;
  const done = pageAction(`event:${start.uid}`);
  try {
    const res = await post('/api/note', { uid: start.uid, text: trailText() });
    reportAction(`Saved the trail as note #${res.seq} on the ${start.short}`, res.server_ms);
    done();
  } catch (err) { setStatus(`Note failed: ${err.message}`); }
}

// A list's heading stops sticking when it, with the column heading under it, is taller than half of the panel's scroll area,
// so a panel dragged short still shows rows. A class on the panel, not a style, since the CSP blocks style attributes.
// The Event page's header follows the same rule where it sticks (960 px and below, when the body scrolls as one): head-tall
// unsticks it, and --head-h is the height that the list's heading sticks under (0 when the header scrolls away).
let headWatch = null;
function watchHeads() {
  if (headWatch) headWatch.disconnect();
  headWatch = null;
  const panel = $('details'), body = $('detailsBody');
  // The Event page's list heading sticks in the work column, which has a height of its own
  const heads = [...body.querySelectorAll('.sticky-head')].filter((h) => !h.closest('.ev-work'));
  const top = body.querySelector(':scope > .ev-head');
  const columns = heads.length ? body.querySelector('li.rel-head') : null;   // the Mark header sticks with the head
  const check = () => {
    panel.classList.toggle('short', heads.some((h) => h.offsetHeight + (columns ? columns.offsetHeight : 0) > body.clientHeight / 2));
    const tall = !!top && top.offsetHeight > body.clientHeight / 2;
    panel.classList.toggle('head-tall', tall);
    if (top && !tall) body.style.setProperty('--head-h', `${top.offsetHeight}px`);
    else body.style.removeProperty('--head-h');
  };
  check();
  if (!heads.length && !top) return;
  headWatch = new ResizeObserver(check);
  headWatch.observe(body);
  for (const h of [...heads, ...(top ? [top] : []), ...(columns ? [columns] : [])]) headWatch.observe(h);
}

export function goBack() {
  const prev = S.back.pop();
  if (!prev) return;
  S.goingBack = true;
  if (prev.key.startsWith('event:')) S.trailVia = 'back';   // an event the trail holds is gone back to, and the trail stays
  prev.reopen();
}

export const button = (label, onclick, attrs = {}) => el('button', { type: 'button', onclick, ...attrs }, label);

export async function copyText(text, what) {
  try { await navigator.clipboard.writeText(text); setStatus(`Copied ${what}`); }
  catch (_) { setStatus(`Could not copy ${what}: the browser blocked clipboard access`); }
}

// A journal head as the page shows it, short, with Copy for all 64 characters
export const headCopy = (head, short) => [el('code', { class: 'journal-head', title: head }, short),
  ' ', button('Copy', () => copyText(head, 'the journal head'), { class: 'quiet small' })];

// The notice after an export or report: the head after the file's entry in the journal, which covers its record
export const headAfter = (res) => el('span', { class: 'head-after' },
  ` Journal head after recording this file: `, ...headCopy(res.head, res.head_short),
  ` (entry #${res.head_seq}). Record it with the file to check the file later.`);

// While the journal's chain is broken, the case is read-only: every change is refused until the
// analyst continues with the break on record from the Case overview
export const readOnlyHint = () => (S.journal?.broken ? [el('p', { class: 'warn read-only' },
  'Read-only: the journal was changed after it was written, so marks, notes, and other changes are refused. ' +
  (S.journal.can_continue ? 'Continue with the break on record from the Case overview, or copy the case folder and investigate first.'
    : 'Copy the case folder and investigate first: a journal with no chained line has no break to continue from.'))] : []);

// Label and value pairs; empty values are left out. Clicking a value copies it, unless the analyst is selecting text.
export function fieldList(rows) {
  const dl = el('dl');
  for (const [label, value, viewValue] of rows) {
    if (value === '' || value == null) continue;
    const text = String(value);
    // A field that can join the view filter gets an add-or-remove action beside it, and one that
    // puts it in the search box. A value holding a double quote can't be written as a search term.
    // An address's toggle is a menu that also offers it at either end.
    const [[field, fieldValue] = []] = viewValue ? Object.entries(viewValue) : [];
    const add = viewValue ? [field in ADDRESS_FIELDS ? addressToggle(viewValue) : viewToggle(viewValue)] : [];
    if (field && !fieldValue.includes('"')) {
      add.push(button('Add to search', (ev) => { ev.stopPropagation(); addToSearch(field, fieldValue); },
                      { class: 'linklike addsearch', title: `Put ${field}:${fieldValue} in the search box` }));
    }
    dl.append(el('dt', {}, label), el('dd', { title: 'Click to copy', onclick: () => {
      if (!String(window.getSelection())) copyText(text, label);
    } }, ...marked(text), ...add));
  }
  return dl.children.length ? dl : null;
}

export function fieldGroup(title, rows) {
  const dl = fieldList(rows);
  return dl ? el('div', { class: 'fieldgroup' }, el('h3', {}, title), dl) : null;
}

// A fold, closed until the analyst opens it, which the browser remembers under `key`.
// `open` opens it for this page only, without changing what is remembered.
export function fold(title, key, body, { cls = '', open = false } = {}) {
  const box = el('details', { class: `fold ${cls}`.trim() }, el('summary', {}, title), ...body);
  let stored = false;
  try { stored = localStorage.getItem(key) === '1'; } catch (_) { /* storage blocked */ }
  box.open = stored || open;
  // The toggle event of an opening that was only for this page is not the analyst's choice
  let forced = open && !stored;
  box.addEventListener('toggle', () => {
    if (forced) { forced = false; if (box.open) return; }
    try { localStorage.setItem(key, box.open ? '1' : '0'); } catch (_) { /* storage blocked */ }
  });
  return box;
}

// Field rows in a fold, with their count in its title. `openOnMark` opens it for this page when a search highlight is
// inside, so the match is in view.
export function foldGroup(title, rows, key, { openOnMark = false } = {}) {
  const dl = fieldList(rows);
  return dl ? fold(`${title} (${dl.children.length / 2})`, key, [dl], { open: openOnMark && !!dl.querySelector('mark') }) : null;
}

// MFT times read like "$SI M..." (MACB letters); spell out which times they are.
export function timeMeaning(desc) {
  const m = /^(\$SI|\$FN) ([MACB.]{4})$/.exec(desc || '');
  if (!m) return desc;
  return `${m[1]} ${[...m[2]].filter((c) => c !== '.').map((c) => MACB[c]).join(', ')} (${m[2]})`;
}

export function parseExtra(ev) {
  if (!ev.extra) return null;
  try { const x = JSON.parse(ev.extra); return x && typeof x === 'object' ? x : null; } catch (_) { return null; }
}

export function artifactGroup(ev, extra) {
  const spec = lookup(ARTIFACT_DETAILS, ev.artifact);
  if (!spec || !extra) return null;
  const [title, keys] = spec;
  const show = (v) => (typeof v === 'object' ? JSON.stringify(v) : v);
  // RECmd's ValueData is the Registry data row, but a plugin's key row has no value, so its summary shows here.
  // A looked-up account's marker and SID show under the account, as Looked up, not among the record's own data.
  const shown = (k) => !(k === 'ValueData' && ev.artifact === 'registry' && ev.registry_data)
    && k !== 'AccountLookedUp' && k !== 'AccountLookedUpSid';
  // Windows writes "-" for an empty EventData value; those stay under Raw fields.
  return fieldGroup(title, (keys || Object.keys(extra)).filter((k) => k in extra && extra[k] !== '-' && shown(k))
    .map((k) => [k, show(extra[k]), dataValue(k, extra[k])]));
}

// Raw columns that are View fields, and an event-data field as a View value.
const RAW_VIEW_FIELD = { host: 'host', tool: 'tool', artifact: 'artifact', log_channel: 'channel', source_file: 'file', run_id: 'run',
  event_code: 'code', event_provider: 'provider', host_name_recorded: 'computer', source_ip: 'ip', source_port: 'port',
  dest_ip: 'dest_ip', dest_port: 'dest_port',
  source_workstation: 'workstation', logon_type: 'logon_type', logon_id: 'logon_id', process_executable: 'process',
  process_command_line: 'command_line', file_path: 'path', registry_path: 'registry_key', registry_value: 'registry_value',
  process_parent_executable: 'parent', process_parent_command_line: 'parent_command_line', registry_data: 'registry_data' };

function dataValue(key, value) {
  // The server quotes the name into a JSON path, so a name holding a quote or backslash can't be a View value.
  if (value == null || typeof value === 'object' || value === '' || value === '-' || key.includes('"') || key.includes('\\')) return null;
  return { [`data.${key}`]: String(value) };
}

export function rawFields(ev, extra) {
  const rows = [];
  for (const [k, v] of Object.entries(ev)) {
    if (NOT_RAW.has(k)) continue;
    const field = RAW_VIEW_FIELD[k];
    rows.push([k, k === 'ts_us' && v != null ? `${v} (${fmtUs(v)} UTC)` : v,
               field && v !== '' && v != null ? { [field]: String(v) } : null]);
  }
  if (ev.extra && !extra) rows.push(['extra', ev.extra]);
  if (extra) {
    for (const [k, v] of Object.entries(extra)) rows.push([`extra.${k}`, typeof v === 'object' ? JSON.stringify(v) : v, dataValue(k, v)]);
  }
  const list = fieldList(rows);
  const count = list ? list.children.length / 2 : 0;
  return fold(`Raw fields (${count})`, RAW_OPEN_KEY, [
    ...(list ? [list] : []),
    // At the end of the list, away from the toggle, so reaching for one can't hit the other.
    el('div', { class: 'raw-foot' }, button('Copy as JSON', () => copyText(JSON.stringify({ ...ev, extra }, null, 2), 'the event as JSON')))],
  { cls: 'raw' });
}

export const LEVEL_RANK = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
// What a kind of event is called, as /api/meta gives it, or its artifact ID.
export const artifactName = (id) => lookup(S.meta?.artifact_names, id) || id;

// An event's pending suggestions as the lists rank them: Malicious, then Suspicious, then Authorized, with ties by source
// name.
const SUGGESTION_RANK = { malicious: 0, suspicious: 1, authorized: 2 };
const suggestionRank = (value) => lookup(SUGGESTION_RANK, value) ?? 3;
function pendingSuggestions(ev) {
  const rank = (x) => suggestionRank(x.value);
  return ev.suggestions.filter((x) => !x.rejected)
    .sort((a, b) => rank(a) - rank(b) || (a.source < b.source ? -1 : a.source > b.source ? 1 : 0));
}

// The badge of the event an Event page shows (also the menu's head): its review state with who marked it and when. An
// unmarked event with a pending suggestion reads as its most severe one, as in the lists.
export function eventBadge(ev) {
  const guess = ev.mark.label === 'Unreviewed' ? pendingSuggestions(ev)[0] : null;
  return markBadge({ mark: guess ? `Suggested: ${guess.value}` : ev.mark.label, mark_who: ev.mark.who, mark_at: ev.mark.at,
                     suggest_source: guess?.source });
}

// The header's second line: what kind of event this is.
export function eventKind(ev) {
  if (ev.artifact === 'evtx') return [ev.message.split(' | ')[0], ev.log_channel].filter(Boolean).join(', ');
  if (ev.artifact === 'hayabusa') return `Hayabusa ${ev.rule_level}: ${ev.rule_title}`;
  return [artifactName(ev.artifact), timeMeaning(ev.ts_desc)].filter(Boolean).join(', ');
}

// Up to two lines on who acted and on what. EVTX gets them from the key fields; the other tools' one-line
// messages already say it (an MFT path and its flags, a prefetch run count, an LNK target).
export function eventSummary(ev) {
  if (ev.artifact !== 'evtx') return ev.message ? [ev.message] : [];
  const lines = [];
  const account = ev.user_name ? (ev.user_domain ? `${ev.user_domain}\\${ev.user_name}` : ev.user_name) : '';
  if (account || ev.source_ip) {
    let who = account || 'Unknown account';
    if (ev.source_ip) who += ` from ${ev.source_ip}${ev.source_port ? `, port ${ev.source_port}` : ''}`;
    if (ev.source_workstation && ev.source_workstation !== '-') who += ` (${ev.source_workstation})`;
    const type = lookup(LOGON_TYPES, ev.logon_type);
    if (ev.logon_type) who += `, ${type ? `${type} (${ev.logon_type})` : `logon type ${ev.logon_type}`}`;
    lines.push(who);
  }
  const registry = [ev.registry_path, ev.registry_value].filter(Boolean).join(' : ') + (ev.registry_data ? ` = ${ev.registry_data}` : '');
  const object = ev.process_command_line || ev.file_path || (ev.registry_path ? registry : '') || ev.process_executable;
  if (object) lines.push(object);
  if (!lines.length) {
    const rest = ev.message.split(' | ').slice(1).join(' | ');
    if (rest) lines.push(rest);
  }
  return lines;
}

// Hayabusa hits for the header: the most severe one as a chip on the summary line, and "+N" for the rest,
// which opens them, one chip each, in the header's third row. `lead` is for the summary line, `rest` the third row's
// node, or null when the event has one hit.
export function hitChips(hits) {
  if (!hits.length) return { lead: [], rest: null };
  const rank = (h) => lookup(LEVEL_RANK, h.level) ?? 9;
  const [top, ...others] = [...hits].sort((a, b) => rank(a) - rank(b));
  const chip = (h) => el('span', { class: `chip level-${h.level}`, title: `Hayabusa ${h.level}: ${h.title}` }, `Hayabusa ${h.level}: ${h.title}`);
  const lead = [chip(top)];
  if (!others.length) return { lead, rest: null };
  const rest = el('div', { class: 'chips', hidden: '' }, ...others.map(chip));
  const more = button(`+${others.length}`, () => {
    rest.hidden = !rest.hidden;
    more.setAttribute('aria-expanded', String(!rest.hidden));
  }, { class: 'linklike more', 'aria-expanded': 'false', title: `${plural(others.length, 'more Hayabusa hit')}:\n` + others.map((h) => `${h.level}: ${h.title}`).join('\n') });
  return { lead: [...lead, more], rest };
}

// The rows the selection list shows at once, as app.css sizes it; it scrolls for the rest
const LIST_ROWS = 8;
// A host name up to this long stays whole in the header; a longer one gives up room for the start of the kind
const LONG_HOST_CHARS = 12;

// The Event page's selection list: the events it lists, kept with the Set in S.selected it was made from (`of`), whose
// events are its ticked rows. A tick or Select all adds to that Set and an untick takes from it, and the row stays
// listed; a shift-click on the timeline adds an event to the list or takes it out. A new Set in S.selected, as a plain
// click or a page that opens one event makes, starts a new list from it. `find`, `scroll`, and `note` keep the list's
// find text, its place, and the verdict zone's note through the events its rows open, and `at` is the event the page
// showed when the list last drew.
export function selectionListing() {
  if (S.listed?.of !== S.selected) S.listed = newListing(S.selected);
  for (const uid of S.selected) S.listed.uids.add(uid);
  return S.listed;
}

// A selection list of `uids`, whose ticked rows are the events of `of`, a Set in S.selected
export const newListing = (of, uids = []) => ({ of, uids: new Set(uids), find: '', scroll: 0, note: '', at: null });

// Take an event out of the selection and out of its list, as a shift-click on the timeline does
export function deselect(uid) {
  S.selected.delete(uid);
  if (S.listed?.of === S.selected) S.listed.uids.delete(uid);
}

// A row's click opens its event on the page, and the list stays as it was: its ticks, its find, its place, and the
// timeline's window
function openListed(e) {
  if (S.focus === e.uid) return;
  S.focus = e.uid;
  S.windowLinks = [];
  draw();
  loadDetails(e.uid, e.ts);
}

// The events a mark of the ticked rows would change, with their current marks, so a group mark can't replace a Malicious
// mark the zone never showed: a caption with the count, Select all, and a find box, then a row for each listed event
// with its tick, its badge, and its text, in time order. The row of the event on the page is highlighted. A tick selects
// its event on the timeline and draws the page again; a click elsewhere on a row opens its event. `chosen` is
// /api/selected's answer for the listed events.
function selectionList(chosen, listing) {
  if (chosen.error) return [el('p', { class: 'muted' }, `Could not list the selected events: ${chosen.error}`)];
  const total = listing.uids.size;
  const redraw = () => { draw(); if (S.focus) loadDetails(S.focus); };
  const rows = chosen.events.map((e) => {
    const box = el('input', { type: 'checkbox', 'aria-label': 'Tick to mark',
                              title: 'A tick selects the event on the timeline, and the marks above act on the selected events' });
    box.checked = S.selected.has(e.uid);
    box.addEventListener('change', () => { if (box.checked) S.selected.add(e.uid); else S.selected.delete(e.uid); redraw(); });
    const onPage = e.uid === S.focus;
    return el('li', { 'data-uid': e.uid, ...(onPage ? { class: 'on-page', 'aria-current': 'true' } : {}),
                      onclick: (ev) => { if (ev.target !== box) openListed(e); } },
              box, markBadge(e), el('span', { class: 'sel-text', title: e.msg }, `${fmtUs(e.ts)}  ${e.host}  ${codePrefix(e)}${e.msg}`));
  });
  const list = el('ul', { class: 'selection-list', 'aria-label': 'Listed events' }, ...rows);
  list.addEventListener('scroll', () => { listing.scroll = list.scrollTop; });
  const caption = el('strong', {}, S.selected.size === total ? `The ${plural(total, 'selected event')}, in time order`
                                                             : `The ${plural(total, 'listed event')}, in time order`);
  const inView = el('span', { class: 'muted sel-in-view' });
  const hiddenTicks = el('span', { class: 'find-ticks', hidden: '' });
  let shown = null;   // the uids of the rows the find shows, or null with no find
  // One button, as on the other ticked lists: Select all, or Select none once every row is ticked; with a find on, it
  // ticks the shown rows, or unticks them once every shown row is ticked
  const all = [...listing.uids].every((uid) => S.selected.has(uid));
  const everyShownTicked = () => shown.size > 0 && [...shown].every((uid) => S.selected.has(uid));
  const selectLabel = () => {
    if (!shown) return all ? 'Select none' : 'Select all';
    return `${everyShownTicked() ? 'Unselect' : 'Select'} the ${shown.size.toLocaleString()} shown`;
  };
  const selectAll = button('Select all', () => {
    if (shown) {
      const every = everyShownTicked();
      for (const uid of shown) { if (every) S.selected.delete(uid); else S.selected.add(uid); }
    } else if (all) S.selected.clear();
    else for (const uid of listing.uids) S.selected.add(uid);
    redraw();
  }, { class: 'linklike' });
  const listed = new Set(chosen.events.map((e) => e.uid));
  const cut = total > chosen.events.length;
  const find = listFind(list, { kept: listing, rows: 'li', cells: '.sel-text', highlight: '.sel-text',
                                covers: 'The selection and the marks still cover', listed: cut ? chosen.events.length : null,
                                total, more: 'events', onApply: (set) => {
    shown = set;
    const n = set ? set.size : rows.length;
    selectAll.textContent = selectLabel();
    inView.hidden = n <= LIST_ROWS;
    inView.textContent = `${LIST_ROWS} of ${n.toLocaleString()} in view; scroll for the rest`;
    const here = set || listed;
    const elsewhere = [...S.selected].filter((uid) => !here.has(uid)).length;
    hiddenTicks.hidden = !elsewhere;
    hiddenTicks.textContent = elsewhere ? `${plural(elsewhere, 'selected event')} ${elsewhere === 1 ? "isn't" : "aren't"} shown here` : '';
  } });
  find.box.append(hiddenTicks);
  const head = el('div', { class: 'sel-caption' }, caption, inView, selectAll, find.box);
  return [head, ...(cut ? [find.foot, list, el('p', { class: 'muted' }, `Listing the first ${chosen.events.length} of ${total}.`)]
                        : [list, find.foot])];
}

// The header's right zone, as the header's grid takes it: the first row is the verdict, then the pill and
// either who set the mark or the one decision a pending suggestion needs; the second row is the other marks, a note
// box, + Tag, and the toggle for Hayabusa's suggested tags. What does not fit in two rows goes to `more`, the header's
// third row: a second pending source, the mark's note, the event's tags and open suggestions, rejected suggestions, the
// read-only hint, and, with several events listed, their list with their marks and ticks (`chosen`, for `listing`), under
// the buttons that mark the `n` selected, the ticked ones.
// The verdict as a pill: the word alone. The identity line's badge stands for the state, so the pill carries none.
const pill = (label) => el('span', { class: `status ${label.toLowerCase()}` }, label);

export function verdictZone(ev, uid, n, chosen = null, listing = null) {
  const several = chosen !== null;
  const total = several ? listing.uids.size : n;
  const label = ev.mark.label;
  // The placeholder is the box's only label and the box is 120 px, so it is short; the long wording is in the title.
  const noteFor = several ? `Note for marking ${plural(n, 'event')} (optional)` : 'Note for this mark (optional)';
  const note = el('input', { type: 'text', class: 'mark-note', placeholder: 'Note (optional)', title: noteFor,
                             'aria-label': noteFor });
  if (several) {
    // The note stays with the list, as its find does, through a tick's redraw and the events its rows open
    note.value = listing.note;
    note.addEventListener('input', () => { listing.note = note.value; });
  }
  // A mark of a selection above CONFIRM_ABOVE events asks first; the question goes under the selection's list
  const slot = el('div', { class: 'confirm-slot' });
  const markButton = (m, extra = '') => button(several ? `${m} (${n})` : m, async () => {
    if (several && !n) { setStatus('Tick the events to mark first.'); return; }
    // The note stays for another try until a mark is written
    if (await applyMark(m, note.value, [...S.selected], { host: slot }) && several) listing.note = '';
  }, { class: `mark-${m.toLowerCase()} ${extra}`.trim() });
  const heading = el('h3', {}, !several ? 'Verdict' : n === total ? `Verdict for ${n.toLocaleString()} selected events`
    : `Verdict for ${n.toLocaleString()} selected of ${total.toLocaleString()} listed events`);
  const tags = tagZone(ev, uid, n, several);   // ATT&CK tactics and techniques, and the analyst's own tags
  const more = [...readOnlyHint()];
  const pending = pendingSuggestions(ev);
  const decision = (x) => el('div', { class: `decision ${x.value}` },
    el('span', {}, el('span', { class: 'lead' }, 'Decision needed:'), ` ${x.source} suggests ${x.value}`),
    button(`Accept as ${markWord(x.value)}`, () => decide('accept', x.source, [uid], { note: note.value }),
           { class: `primary mark-${x.value}` }),
    button('Reject', () => decide('reject', x.source, [uid], { note: note.value }),
           { title: 'Reject the suggestion; the note, if any, is kept with the rejection' }));
  let line, marks;
  if (several) {
    line = [heading];
    marks = [...MARKS.map((m) => markButton(m)), note];
    more.push(...selectionList(chosen, listing), slot);
  } else if (label === 'Unreviewed') {
    const [first, ...rest] = pending.map(decision);   // the first source sits by the identity, the others below it
    line = [heading, pill('Unreviewed'),
            ...(first ? [first] : [el('span', { class: 'muted' }, 'Not reviewed yet')])];
    more.push(...rest);
    marks = [el('span', { class: 'muted' }, pending.length ? 'Or mark' : 'Mark'),
             ...MARKS.filter((m) => m !== 'Unreviewed').map((m) => markButton(m)), note];
  } else {
    const by = ev.mark.who ? `by ${ev.mark.who}${ev.mark.at ? `, ${fmtAt(ev.mark.at)}` : ''}` : '';
    line = [heading, pill(label), ...(by ? [el('span', { class: 'muted' }, by)] : [])];
    if (ev.mark.note) more.push(el('div', { class: 'mark-note-text' }, `Note: ${ev.mark.note}`));
    marks = [el('span', { class: 'muted' }, 'Change'), ...MARKS.filter((m) => m !== label).map((m) => markButton(m, 'quiet')), note];
  }
  more.push(...tags.rows);
  const finding = findingRow(ev, several ? [...S.selected] : [uid]);   // the findings this event is in, and + Finding
  more.push(...finding.rows);
  for (const x of ev.suggestions.filter((y) => y.rejected)) {
    const why = lookup(ev.rejection_notes, x.source);   // the note the rejection kept
    more.push(el('div', { class: 'verdict-row small' }, el('span', { class: 'muted' }, `Rejected: ${x.source} suggested ${x.value}` +
                                                         (why ? `. Note: "${why.text}"` : '')),
                 button('Restore', () => decide('restore', x.source, [uid]), { class: 'quiet' })));
  }
  const zone = el('div', { class: 'ev-verdict' }, el('div', { class: 'verdict-line' }, ...line),
                  el('div', { class: 'verdict-row' }, ...marks, tags.plus, finding.plus, ...(tags.toggle ? [tags.toggle] : [])));
  return { zone, more };
}

// What a case format upgrade that changed event IDs says on the event's page: that it was opened by an
// earlier ID, and each ID named before an upgrade that may have meant this event or another, whose entries stay on it.
function idNotes(ev) {
  const at = (seqs) => seqs.map((s) => `#${s}`).join(' and ');
  const notes = [];
  if (ev.id_changed) {
    notes.push(el('div', { class: 'muted id-changed' },
      `This event's ID changed at ${at(ev.id_changed.seqs)}, when the case format was upgraded; ` +
      `it was opened by its earlier ID, ${ev.id_changed.from}.`));
  }
  if (ev.id_also_named) {   // this ID names this event, and an upgrade also moved it to another
    const now = ev.id_also_named.now;
    notes.push(el('div', { class: 'muted id-also-named' },
      `Before the case format upgrade at ${at(ev.id_also_named.seqs)}, this ID named another event, which has the ID ` +
      `${now} now. The entries made under this ID before then are on that event. `,
      button('Open that event', () => { S.selected = new Set([now]); S.focus = now; S.windowLinks = []; draw(); loadDetails(now); },
             { class: 'linklike' })));
  }
  for (const u of ev.unplaced || []) {
    notes.push(el('div', { class: 'muted id-unplaced' },
      `Before #${u.seq}, the ID ${u.id} may have meant this event or ${plural(u.others, 'other event')}; the entries ` +
      'made under it stay on that ID. Mark this event again if they meant it.'));
  }
  return notes;
}

// The time the page shows an event at, which lets the server find the event without reading every event's ID: the
// caller's, the Event page's own when it shows the event, or the timeline's tick. Without one, or
// when an offset has moved the event since, the server reads them all.
export function shownAt(uid, ts = null) {
  if (ts != null) return ts;
  if (S.focusEvent && S.focusEvent.uid === uid) return S.focusEvent.adjusted;
  const tick = S.data && S.data.events && S.data.events.find((e) => e.uid === uid);
  return tick ? tick.ts : null;
}

export function eventUrl(uid, ts = null) {
  const at = shownAt(uid, ts);
  return `/api/event?uid=${encodeURIComponent(uid)}` + (at == null ? '' : `&ts=${at}`);
}

// The listed events and their marks, for the verdict zone's list; an error's message in place of them.
async function listedEvents(listing) {
  const uids = [...listing.uids].slice(0, LISTED_EVENTS);
  try { return await api(`/api/selected?${uids.map((u) => `uid=${encodeURIComponent(u)}`).join('&')}`); }
  catch (err) { return { error: err.message, events: [] }; }
}

const readEvent = (uid, ts = null) => api(eventUrl(uid, ts)).then((res) => res.event);

// The event in focus as the pages that name it read it, such as Save trail and New finding
const focusEventOf = (uid, ev) => ({ uid, host: ev.host, recorded: ev.ts_us, adjusted: ev.adjusted_ts_us, short: eventShort(ev),
                                     label: eventLabel(ev) });

// Fill S.focusEvent for the event in focus without drawing its page or claiming the panel, as a reload that comes back
// to another page does. A failed read leaves it empty, and the pages then say "the selected event".
export async function fillFocusEvent(uid) {
  let ev;
  try { ev = await readEvent(uid); } catch (_) { return; }
  if (S.focus === uid) S.focusEvent = focusEventOf(uid, ev);
}

// The text typed in the Event page's Notes box and its event, so a redraw of that event's page, as a tick in the
// selection list makes, keeps it until the note is added; another event's page starts empty
let typedNote = { uid: null, text: '' };

export async function loadDetails(uid, ts = null) {
  const latest = claimDetails();
  const drew = pageRead();
  const via = S.trailVia;   // set by a click on a pivot's list, or by Back: how the event opened relates to the trail
  S.trailVia = false;
  const listing = selectionListing();
  const several = listing.uids.size > 1;
  let ev, chosen;
  try { [ev, chosen] = await Promise.all([readEvent(uid, ts), several ? listedEvents(listing) : null]); }
  catch (err) {
    if (latest()) setPage('event', [el('p', { class: 'pad' }, `Could not load the event: ${err.message}`)]);
    return;
  }
  if (S.focus !== uid || !latest()) return;   // a later click or page has moved on
  if (ev.id_changed && ev.event_uid !== uid) {
    // An earlier ID a case format upgrade changed: the page goes on as the event's own, so a mark or a
    // note made here names the event's current ID
    deselect(uid);
    S.selected.add(ev.event_uid);
    S.focus = uid = ev.event_uid;
    draw();
  }
  S.focusEvent = focusEventOf(uid, ev);
  trailEvent(uid, ev, via);
  setPairLink(uid, ev);   // the dashed link to its pair, when the clock check paired it with the capture

  // The header: two rows over the two columns, and a third only when it has something to say. Row 1 is the
  // identity (the badge, the time, the host, and the kind), with the verdict and its one decision beside it; row 2 is the
  // host's clock chip, when the host has an offset, then the summary, with the other marks beside it.
  // Its left edge takes the color of the current mark. The time's hover has the recorded time and the host's own clock.
  const offsetS = ev.offset_us / 1e6;
  const offsetText = `${offsetS > 0 ? '+' : ''}${offsetS} s`;
  const kind = eventKind(ev);
  // A time the host's clock didn't write, such as Autoruns' PE link time, has no clock note and no local time on the
  // host. The host's offset still moves it, so its chip names that offset, not a clock adjustment.
  const hostClock = ev.host_clock !== false;
  // An aligned host's plain event: the clock note is the hover of the chip, or of the time when the clock needed no
  // offset, not a row. That cell takes the focus when aligning removed the button that had it (clock.js).
  const folded = hostClock && clockFolds(ev);
  const holds = folded ? { 'data-clock': ev.clock.state, tabindex: '-1' } : {};
  const timeTitle = [folded && !offsetS ? clockHover(ev) : '', offsetS ? `Recorded ${fmtUs(ev.ts_us)} UTC` : '',
                     hostClock ? hostLocalText(ev) : ''].filter(Boolean).join('\n');
  const chip = !offsetS ? null
    : hostClock ? el('span', { class: 'chip clock-chip', title: `${folded ? `${clockHover(ev)}\n` : ''}Recorded ${fmtUs(ev.ts_us)} UTC`,
                               ...holds },
                     `${folded ? 'Aligned' : 'Clock adjusted'} ${offsetText}`)
    : el('span', { class: 'chip clock-chip', title: `Recorded ${fmtUs(ev.ts_us)} UTC\nThe offset set for ${ev.host} moves every ` +
                                                    `time on ${ev.host}, this one too, though ${ev.host}'s clock didn't write it.` },
         `Host offset ${offsetText}`);
  // The identity line starts with the badge, whose hover says who marked the event and when
  const ident = el('div', { class: ev.host.length > LONG_HOST_CHARS ? 'ev-ident long-host' : 'ev-ident' }, eventBadge(ev),
    el('span', { class: 'time', ...(timeTitle ? { title: timeTitle } : {}), ...(offsetS ? {} : holds) },
       ev.adjusted_ts_us == null ? 'No time' : `${fmtUs(ev.adjusted_ts_us)} UTC`),
    el('span', { class: 'host', title: ev.host }, ev.host),
    el('span', { class: 'kind', title: kind }, kind));
  const hits = hitChips(ev.hits);
  const summary = eventSummary(ev).join(' · ');
  // The clock chip is the summary row's first item, under the time it explains, so it takes no room from the kind
  const sum = el('div', { class: 'ev-sum' }, ...(chip ? [chip] : []), ...hits.lead,
                 ...(summary ? [el('span', { class: 'ev-summary', title: summary }, summary)] : []));
  const verdict = verdictZone(ev, uid, S.selected.size, chosen, listing);
  const headMore = [
    // Moved by a split by recorded computer: the host folder it came from, and the split's journal entry
    ...(ev.split ? [el('div', { class: 'muted split-from' },
                       `Loaded from ${ev.split.from}, shown on ${ev.host} (split #${ev.split.seq})`)] : []),
    ...idNotes(ev), ...(folded || !hostClock ? [] : clockNote(ev)), ...(hits.rest ? [hits.rest] : []), ...verdict.more,
  ];

  // Left: the evidence, most telling fields first, raw fields last.
  const account = ev.user_name ? (ev.user_domain ? `${ev.user_domain}\\${ev.user_name}` : ev.user_name) : '';
  const typeName = lookup(LOGON_TYPES, ev.logon_type);
  const logonType = ev.logon_type && typeName ? `${ev.logon_type} (${typeName})` : ev.logon_type;
  const extra = parseExtra(ev);
  const vv = (field, value) => (value === '' || value == null ? null : { [field]: String(value) });   // a View value
  // An account known only by its SID, named from the host's 4624s and 4672s, says so beneath it:
  // the name was looked up, not recorded in this event.
  const lookedUp = extra && typeof extra.AccountLookedUp === 'string' ? extra.AccountLookedUp : '';
  if (typedNote.uid !== uid) typedNote = { uid, text: '' };
  const typed = typedNote;
  const noteInput = el('input', { type: 'text', placeholder: 'Add a note to this event', size: '28' });
  noteInput.value = typed.text;
  noteInput.addEventListener('input', () => { typed.text = noteInput.value; });
  const saveNote = async () => { if (await addNote(uid, noteInput.value)) typed.text = ''; };
  noteInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') saveNote(); });
  // A retracted note stays, struck through; the others can be retracted.
  const notes = (ev.notes || []).length
    ? el('ul', { class: 'notes' }, ...ev.notes.map((x) => el('li', { class: x.retracted ? 'gone' : '' },
        el('span', { class: 'muted' }, `${fmtAt(x.at)}, ${x.who}: `), x.text,
        x.retracted ? el('span', { class: 'muted' }, ` (retracted by ${x.retracted.who}, ${fmtAt(x.retracted.at)})`)
                    : button('Retract', () => retractNote(uid, x.seq), { class: 'retract', title: 'The note stays on record, struck through' }))))
    : el('p', { class: 'muted' }, 'No notes yet.');
  // History folds with its count, which follows its request: "30+" when the request's limit was reached
  const history = el('div', { class: 'ev-history' });
  const historyFold = fold('History', HISTORY_OPEN_KEY, [history], { cls: 'history-fold' });
  loadHistory(uid, history).then((rows) => {
    if (rows) historyFold.firstChild.textContent = `History (${rows.length >= HISTORY_LIMIT ? `${HISTORY_LIMIT}+` : rows.length})`;
  });
  const facts = [
    el('div', { class: 'ev-message' }, ...marked(ev.message)),
    caveatBox(ev.caveat),   // what this kind of record does not prove, beside the record and above the fields
    fieldGroup('Account and logon', [['Account', account, vv('user', account)], ['Looked up', lookedUp],
                                     ['Logon type', logonType, vv('logon_type', ev.logon_type)],
                                     ['Logon ID', ev.logon_id, vv('logon_id', ev.logon_id)], ['Source IP', ev.source_ip, vv('ip', ev.source_ip)],
                                     ['Source port', ev.source_port, vv('port', ev.source_port)],
                                     ['Destination IP', ev.dest_ip, vv('dest_ip', ev.dest_ip)],
                                     ['Destination port', ev.dest_port, vv('dest_port', ev.dest_port)],
                                     ['Source workstation', ev.source_workstation, vv('workstation', ev.source_workstation)]]),
    fieldGroup('Process, file, and registry', [['Process', ev.process_executable, vv('process', ev.process_executable)],
                                               ['Command line', ev.process_command_line, vv('command_line', ev.process_command_line)],
                                               ['Parent process', ev.process_parent_executable, vv('parent', ev.process_parent_executable)],
                                               ['Parent command line', ev.process_parent_command_line,
                                                vv('parent_command_line', ev.process_parent_command_line)],
                                               ['File', ev.file_path, vv('path', ev.file_path)],
                                               ['Registry key', ev.registry_path, vv('registry_key', ev.registry_path)],
                                               ['Registry value', ev.registry_value, vv('registry_value', ev.registry_value)],
                                               ['Registry data', ev.registry_data, vv('registry_data', ev.registry_data)]]),
    artifactGroup(ev, extra),
    // The provenance strip already names the tool, run, file, record, and hash, so the record and its source fold into one
    // group; a search highlight inside it opens it for this page, so the match is in view
    foldGroup('Record and source', [
      ['Time meaning', timeMeaning(ev.ts_desc)],
      ['Recorded time', offsetS ? `${fmtUs(ev.ts_us)} UTC, before the ${offsetText} ${hostClock ? 'clock' : 'host'} offset` : ''],
      ['Event ID', ev.event_code, vv('code', ev.event_code)], ['Provider', ev.event_provider, vv('provider', ev.event_provider)],
      ['Channel', ev.log_channel, vv('channel', ev.log_channel)],
      ['Record ID', ev.record_id], ['Rule', ev.rule_title ? `${ev.rule_title} (${ev.rule_level})` : ''],
      ['Computer name recorded', ev.host_name_recorded, vv('computer', ev.host_name_recorded)],
      ...(ev.split ? [['Host', ev.host, vv('host', ev.host)], ['Host folder', ev.origin_host]]
                   : [['Host folder', ev.host, vv('host', ev.host)]]),
      ['Tool', [toolName(ev.tool), ev.tool_version].filter(Boolean).join(' '), vv('tool', ev.tool)],
      ['Run', ev.run_id, vv('run', ev.run_id)], ['Artifact', ev.artifact, vv('artifact', ev.artifact)],
      ['Evidence file', ev.source_file, vv('file', ev.source_file)],
      citedHashRow(ev), ['Source record', ev.source_record],
      ['Event UID', ev.event_uid]], RECORD_OPEN_KEY, { openOnMark: true }),
    rawFields(ev, extra),
    el('h3', {}, 'Notes'),
    notes,
    el('div', { class: 'actions' }, noteInput, button('Add note', saveNote)),
    historyFold,   // every journal entry for this event
  ].filter(Boolean);

  // Right: the next pivots for this kind of event, and the analyst's work on it. The pivots draw at once and
  // their counts follow.
  const act = {
    run: (row, more) => pivot(uid, row.pivot, row.seconds, row.ip || null,
                              { ...more, label: row.label, ...(row.name ? { name: row.name } : {}) }),
    search: (term, hint) => {
      if (!term) { $('search').focus(); setStatus(`Type ${hint} into the search box, then press Enter.`); return; }
      trailPivot({ type: 'pivot', uid, kind: 'search', term, label: `Search ${term}`, total: null });
      refreshTrail();
      runSearch(term);
    },
    editWindow: saveWindow,
  };
  const work = [pivotPanel(ev, uid, act), el('div', { id: 'relatedList', class: 'related' })];

  const when = ev.adjusted_ts_us == null ? '' : ` at ${fmtUs(ev.adjusted_ts_us).slice(11, 19)}`;
  const bar = reviewBar(ev, uid);   // Review one by one: where the analyst is in the queue, and its decisions
  // A new selection drawn on the page of a list's event, as a plain click on that event makes, leaves the list behind. The
  // list's page joins Back, named by the list, while the list still holds that event and another, as its reopen needs.
  const prior = S.page?.group;
  const leaves = prior?.uids && prior !== listing && prior.uids.size > 1 && prior.uids.has(uid)
    ? `the ${plural(prior.uids.size, 'listed event')}` : null;
  setPage('event', [
    ...(bar ? [bar] : []),
    el('div', { class: `ev-head ${ev.mark.label.toLowerCase()}` }, ident, sum, verdict.zone,
       ...(headMore.length ? [el('div', { class: 'ev-head-more' }, ...headMore)] : [])),
    provenanceLine(ev),
    el('div', { class: 'ev-body' }, el('div', { class: 'ev-facts', 'data-scroll': 'facts' }, ...facts),
       el('div', { class: 'ev-work', 'data-scroll': 'work' }, ...work)),
  ], { key: `event:${uid}`, title: `the ${ev.host} event${when}`, group: several ? listing : groupReviewOf(uid), leaves,
       // Back to an event of a selection list brings the list back, with its ticks as they were left, while the list still
       // holds that event and another; otherwise the event is selected alone
       reopen: () => {
         if (several && listing.uids.size > 1 && listing.uids.has(uid)) { S.selected = listing.of; S.listed = listing; }
         else S.selected = new Set([uid]);
         S.focus = uid; S.windowLinks = []; draw(); loadDetails(uid);
       } });
  if (several) {
    // The list keeps its place, and comes to the row of the event on the page when the page has moved to another event,
    // unless the find hides that row
    const list = $('detailsBody').querySelector('.selection-list');
    const row = list?.querySelector('li.on-page:not(.find-out)');
    if (list) list.scrollTop = listing.scroll;
    if (row && listing.at !== uid) {
      const r = row.getBoundingClientRect(), box = list.getBoundingClientRect();
      if (r.top < box.top || r.bottom > box.bottom) list.scrollTop += r.top - box.top;
    }
    listing.at = uid;
  }
  renderRelated();
  drew(`event:${uid}`, () => loadDetails(uid, ts));
}

// The Record and source fold's hash row: the intake hash the page cites (provenance.files), which for output found in the
// evidence is the output file's, not the hash of the file the event names, so the row names its file then. With no
// single file cited, as for a load of several output files, it points to the provenance line, which says why.
function citedHashRow(ev) {
  const p = ev.provenance;
  const files = p.files ?? [ev.source_file];
  if (p.state === 'error' || files.length !== 1) return ['Evidence SHA-256', 'see the provenance line'];
  const label = files[0] === ev.source_file ? 'Evidence SHA-256' : `SHA-256 of ${files[0].split('/').pop()}`;
  return [label, ev.evidence_sha256 || 'not in manifest'];
}

// Provenance in one line: the tool and run that read the event, the evidence file
// and record, the file's hash against the intake manifest, and the build that is showing it. A part that does not fit is
// cut with an ellipsis and has its whole text in its hover; the hash part is never cut, so "differs from intake" shows.
function provenanceLine(ev) {
  const p = ev.provenance;
  const sha = p.sha256 ? [el('b', { title: p.sha256 }, `${p.sha256.slice(0, 4)}…${p.sha256.slice(-4)}`), ' '] : [];
  const part = (cls, ...nodes) => {
    const node = el('span', { class: `prov-part ${cls}` }, ...nodes);
    if (cls !== 'sha') node.title = node.textContent;
    return node;
  };
  const bold = (text, title = '') => el('b', title ? { title } : {}, text);
  // The hover says what a match rests on, and why a file isn't said to match while a line of the check log that can't
  // be read may have named it
  const recorded = `(${plural(p.checks, 'check')} recorded)`;
  let hover = '';
  if (p.state === 'matches') {
    hover = `No check since intake has found this file changed ${recorded}.`;
  } else if (p.state === 'uncounted') {
    const n = p.unreadable_lines;
    hover = `${plural(n, 'line')} of verification.jsonl could not be read, so a problem ${n === 1 ? 'it holds' : 'they hold'} ` +
            `with this file is not counted. No check that could be read has found the file changed ${recorded}.`;
  }
  const tool = part('tool', 'Read by ', bold([toolName(ev.tool), ev.tool_version].filter(Boolean).join(' ') || 'unknown'), ev.run_id ? `, run ${ev.run_id}` : '');
  if (ev.tool) tool.title += `. Tool ID: ${ev.tool}`;
  return el('div', { class: 'prov', 'aria-label': 'Provenance' },
    tool,
    part('file', 'from ', bold(ev.source_file || '(no file)', ev.source_file), ev.source_record ? ', record ' : '',
         ...(ev.source_record ? [bold(ev.source_record.length > 40 ? `${ev.source_record.slice(0, 40)}…` : ev.source_record, ev.source_record)] : [])),
    part('sha', 'SHA-256 ', ...sha, el('span', { class: `prov-check ${p.state}`, title: hover }, p.text)),
    part('build', 'shown by build ', bold(S.meta.build || 'unknown')));
}

// Redraw the band after a pivot added a step, so the trail and the note it saves hold the same steps.
export function refreshTrail() { renderBand(); }

// Back to a step of the trail: an event's page, or the pivot's list from the event it was taken from. The trail keeps every
// step; those after this one stay, dimmed, until a new pivot replaces them.
async function goToStep(i) {
  const step = S.trail[i];
  S.trailAt = i;
  S.selected = new Set([step.uid]);
  S.focus = step.uid;
  S.windowLinks = [];
  draw();
  renderBand();   // the band marks the step at once, while its page loads
  if (step.kind === 'search') { runSearch(step.term); return; }
  await loadDetails(step.uid, step.ts ?? null);
  if (step.type === 'pivot') await pivot(step.uid, step.kind, step.seconds, step.ip, step.more || {});
}

// The Event page of the event in focus, as an action noted it (pageAction): a mark, a decision, or a tag redraws it when
// it answers only while the panel shows it and no page was asked for since. A list's mark or tag redraws the list instead.
export const focusedPageAction = () => (S.focus ? pageAction(`event:${S.focus}`) : () => false);

// The timeline and counts follow a write the server has answered: the lanes, the window's data, the case's counts, and an
// open View panel's. The write is done once its answer arrives, so a reload that fails doesn't fail it, and lanes that
// don't reload don't keep the window's data and the counts from following. Returns the message of the lanes' failure, else
// of the window's data's, or '' when both reloaded. A window whose data fails to load also says so on the status line
// (data.loadView), which the write's line then replaces.
export async function reloadTimeline() {
  let failed = '';
  try { await reloadLanes(); } catch (err) { failed = err.message; }
  const viewFailed = await fetchView();
  refreshCounts();
  refreshViewCounts();
  return failed || viewFailed;
}

// The status line's last action for a write, set after the redraw so that it stays. With the message of a reload that
// failed (reloadTimeline), it says so after what was written, and has no server time, which is the write's. That lasts
// until the window's data next loads, when the line says only what was written (data.showData).
export function reportWrite(text, ms, reloadError = '') {
  if (reloadError) {
    reportAction(`${text}; the timeline didn't reload: ${reloadError}`, null);
    S.lastAction.onLoad = { text, ms };
  } else reportAction(text, ms);
}

// Returns whether the mark was written, so a list keeps its ticks and note after one that failed: a mark counts as
// written once the server has answered, whether or not the timeline then reloads.
// A hand-picked selection above CONFIRM_ABOVE events asks first, in `host` or the page's confirm slot, and
// the mark then carries the count the analyst confirmed.
export async function applyMark(label, note, uids = [...S.selected], { host = null } = {}) {
  if (!uids.length) return false;
  const consent = {};
  if (uids.length > CONFIRM_ABOVE) {
    const action = label === 'Unreviewed' ? `Set ${plural(uids.length, 'event')} back to Unreviewed` : `Mark ${plural(uids.length, 'event')} ${label}`;
    if (!await askSelection({ action, uids, cls: `mark-${label.toLowerCase()}`, host })) return false;
    consent.confirmed = { count: uids.length };
  }
  const done = focusedPageAction();
  let res;
  try { res = await post('/api/mark', { uids, value: MARK_VALUE[label], note, ...consent }); }
  catch (err) { setStatus(`Mark failed: ${err.message}`); return false; }
  const reloadError = await reloadTimeline();
  const what = uids.length === 1 ? 'one event' : `${uids.length.toLocaleString()} events`;
  reportWrite(label === 'Unreviewed' ? `Set ${what} back to Unreviewed` : `Marked ${what} ${label}`, res.server_ms, reloadError);
  done();
  return true;
}

// What a reject leaves of its `changed` events, `marked` of which carry a mark: rejecting a suggestion on an event already
// marked, as the right-click menu can, leaves the mark.
function rejectLeaves(changed, marked) {
  const unmarked = changed - marked;
  if (!marked) return changed === 1 ? 'the event stays Unreviewed' : 'the events stay Unreviewed';
  if (!unmarked) return changed === 1 ? 'the event keeps its mark' : 'the events keep their marks';
  return `${plural(marked, 'event keeps its mark', 'events keep their marks')} and ` +
         `${unmarked.toLocaleString()} ${unmarked === 1 ? 'stays' : 'stay'} Unreviewed`;
}

// What the status line says a suggestion decision did, from the server's answer. An accept names the mark it gave, or each
// mark and its count when a source's suggestions differ. A reject says what becomes of the events.
export function decisionWords(decision, source, { changed, skipped = 0, accepted = {}, marked = 0 }) {
  const count = changed ? plural(changed, `${source} suggestion`) : `no ${source} suggestions`;
  let words = `Restored ${count}`;
  if (decision === 'accept') {
    const marks = Object.entries(accepted).sort(([a], [b]) => suggestionRank(a) - suggestionRank(b));
    words = `Accepted ${count}`;
    if (marks.length === 1) words += ` as ${markWord(marks[0][0])}`;
    else if (marks.length) words += `: ${marks.map(([value, n]) => `${n.toLocaleString()} as ${markWord(value)}`).join(', ')}`;
  } else if (decision === 'reject') {
    words = changed ? `Rejected ${count}; ${rejectLeaves(changed, marked)}` : `Rejected ${count}`;
  }
  return skipped ? `${words}. ${skipped.toLocaleString()} skipped as decided meanwhile` : words;
}

// Accept, reject, or restore one source's suggestions: for the given events, one group of the Suggestions
// page, or all of its pending ones. `fromEvent` re-renders the Event page; other pages refresh themselves. An accept's
// `note` is journaled after its fixed text. A group action the analyst confirmed names its exact
// events in `uids` and the count the confirm stated in `confirmed`; the status line then says how many the server
// skipped as decided meanwhile. `pendingOnly` holds a decision on named events to the same, with no question asked.
export async function decide(decision, source, uids, { group = null, groupBy = null, fromEvent = !!uids, note = '', confirmed = null, pendingOnly = false } = {}) {
  const done = fromEvent ? focusedPageAction() : () => false;
  const body = group != null ? { decision, source, group, group_by: groupBy } : uids ? { decision, source, uids } : { decision, source };
  if (note.trim()) body.note = note;
  if (confirmed) body.confirmed = confirmed;
  if (pendingOnly) body.pending_only = true;
  let res;
  try { res = await post('/api/suggestion', body); }
  catch (err) { setStatus(`Suggestion change failed: ${err.message}`); return null; }
  const reloadError = await reloadTimeline();
  reportWrite(decisionWords(decision, source, res), res.server_ms, reloadError);   // after the redraw
  done();
  return res;
}

// A list's rejection is out, from its request until its answer is handled. A second click sends nothing, even on a button a
// tick has drawn since: the server would skip every event the first decided, and that answer would replace the first's on
// the status line.
let rejectOut = false;

// Reject the pending suggestions of a list's ticked events, whichever sources suggest them, which the server finds. Above
// CONFIRM_ABOVE events it asks first, and the entries then carry the count the analyst confirmed. `clicked`, the list's
// button, is off from the request on: a write that went through leaves it off for the redraw to replace, and a refused one
// turns it on for another try. Returns the server's answer, whose `changed` is 0 when every event was decided meanwhile, or
// null when the click wrote nothing: a Cancel, a refusal, or a click while a rejection is out. A list then keeps its ticks
// and note.
export async function rejectTicked(uids, note, clicked) {
  if (!uids.length || rejectOut) return null;
  const consent = {};
  if (uids.length > CONFIRM_ABOVE) {
    const n = uids.length.toLocaleString();
    const asked = await askSelection({ action: `Reject the suggestions on ${plural(uids.length, 'event')}`, uids,
                                       effect: `All ${n} stay Unreviewed, and their sources stop suggesting them.`,
                                       record: 'The journal records one entry for each source, listing its events, with your name and the time.' });
    if (!asked) return null;
    consent.confirmed = { count: uids.length };
  }
  rejectOut = true;
  clicked.disabled = true;
  try {
    const res = await sendRejection({ uids, note, ...consent });
    if (!res) {
      clicked.disabled = false;
      clicked.focus();
    }
    return res;
  } finally {
    rejectOut = false;
  }
}

// rejectTicked's request, and the timeline and the status line after it. Returns the answer, or null for a refusal.
async function sendRejection(body) {
  const done = focusedPageAction();
  let res;
  try { res = await post('/api/reject_ticked', body); }
  catch (err) { setStatus(`Suggestion change failed: ${err.message}`); return null; }
  const reloadError = await reloadTimeline();
  const skipped = res.skipped ? `${plural(res.skipped, 'event')} skipped as decided meanwhile` : '';
  const stay = res.changed === 1 ? 'it stays' : 'they stay';
  reportWrite(res.changed ? `Rejected suggestions on ${plural(res.changed, 'event')} (${res.sources.join(', ')}); ${stay} Unreviewed${skipped ? `, ${skipped}` : ''}`
    : `Rejected no suggestion: ${skipped}`, res.server_ms, reloadError);
  done();
  return res;
}
