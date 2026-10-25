import { clockCell, refocus, renderClockSwitch } from './clock.js';
import { $, api, EITHER_END_PIVOT, el, fmtAt, KEY_LABEL, PIVOTS, plural, post, ROLES, S, setStatus } from './core.js';
import { refreshCounts } from './counts.js';
import { fetchView, fitTitle } from './data.js';
import { artifactName, button, focusedPageAction, loadDetails, pageAnswered, settleRedraw, showingPage } from './event_page.js';
import { applyFilter, filterCount, openItemMenu, renderFilterState, toggleFilterPanel } from './filters.js';
import { reloadLanes } from './lanes.js';
import { menuItem } from './quick_menu.js';
import { dropGoneHosts } from './view.js';

// ---------- Hosts panel and host roles ----------

export const hostInfo = (name) => S.meta.hosts.find((h) => h.host === name);

// Where a host's role came from: the guess and its reason, or who set or confirmed it.
export function roleStatus(h) {
  if (h.role_source === 'guess') return `Guessed: ${h.role_reason}`;
  const who = h.role_by ? ` by ${h.role_by}${h.role_at ? `, ${fmtAt(h.role_at)}` : ''}` : '';
  return h.role === h.guessed_role ? `Confirmed${who}. ${h.role_reason}.`
    : `Set${who}. The evidence suggested ${h.guessed_role}: ${h.role_reason}.`;
}

// The hosts in a lane: the host itself, or the hosts in a role lane's events.
export function hostsUnder(row) {
  if (row.key === 'host') return [row.label];
  const hi = S.groupby.indexOf('host');
  if (hi < 0 || !row.keys) return S.meta.hosts.filter((h) => h.role === row.label).map((h) => h.host);
  const names = new Set();
  for (const lane of S.lanes) if (row.keys.every((k, i) => lane.keys[i] === k)) names.add(lane.keys[hi]);
  return [...names];
}

// Host and role lane labels say when a role is still a guess.
export function guessBadge(row) {
  if (row.key === 'host') {
    const h = hostInfo(row.label);
    if (h && h.role_source === 'guess') {
      return el('span', { class: 'guess', title: `Role guessed as ${h.role}: ${h.role_reason}. Right-click to confirm or change it.` },
                'guessed');
    }
  } else if (row.key === 'role') {
    const n = hostsUnder(row).map(hostInfo).filter((h) => h && h.role_source === 'guess').length;
    const which = n === 1 ? '1 of these hosts has' : `${n} of these hosts have`;
    if (n) return el('span', { class: 'guess', title: `${which} a guessed role. Right-click to confirm.` }, `${n} guessed`);
  }
  return null;
}

// A value typed beside a host is an IP address when it is four dotted numbers or holds a colon, as IPv6 does. Any other
// value is a name: dc1.ad is a name, though each of its characters could be part of an IPv6 address.
const isAddress = (value) => /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(':');

export function renderHosts() {
  renderSplits();
  const conflicts = new Set(S.meta.identity_conflicts || []);
  const body = $('hostsTable').querySelector('tbody');
  body.replaceChildren(...S.meta.hosts.map((h) => {
    const roles = ROLES.includes(h.role) ? ROLES : [...ROLES, h.role];
    const roleSelect = el('select', { onchange: () => hostEdit({ host: h.host, role: roleSelect.value }) },
      ...roles.map((r) => { const o = el('option', { value: r }, r); if (r === h.role) o.selected = true; return o; }));
    const roleCell = el('td', {}, roleSelect,
      ...(h.role_source === 'guess' ? [' ', button('Confirm', () => confirmRoles([h.host]), { title: 'Journal this role as checked' })] : []),
      el('div', { class: 'role-status' }, roleStatus(h)));
    const review = h.review.length ? el('ul', { class: 'review' }, ...h.review.map((r) => el('li', {}, r)))
      : el('span', { class: 'muted' }, 'No');
    // The OS from the host's live SOFTWARE hive; the hive file read is beneath it.
    const os = h.os && h.os.display
      ? el('td', { class: 'os', title: [h.os.edition, h.os.installation_type, h.os.install_date && `installed ${h.os.install_date}`,
                                       h.os.product !== h.os.display.split(',')[0] && `the registry names it ${h.os.product}`,
                                       h.os.source].filter(Boolean).join('\n') },
           h.os.display, el('div', { class: 'os-source' }, 'SOFTWARE hive'))
      : el('td', { class: 'muted' }, 'Not recorded');
    // Names and IPs come from the evidence; the analyst can remove a wrong one, for example to settle a conflict.
    const ident = (value, op) => el('span', { class: conflicts.has(value) ? 'ident conflict' : 'ident',
                                              title: conflicts.has(value) ? 'Another host also claims this' : '' }, value,
      button('×', () => hostEdit({ host: h.host, op, value }), { class: 'remove', title: `Remove ${value} from ${h.host}`,
                                                                  'aria-label': `Remove ${value} from ${h.host}` }));
    const add = el('input', { type: 'text', placeholder: 'IP or hostname, then Enter', size: '24' });
    add.addEventListener('keydown', (ev) => {
      if (ev.key !== 'Enter' || !add.value.trim()) return;
      const value = add.value.trim();
      hostEdit({ host: h.host, op: isAddress(value) ? 'add_ip' : 'add_name', value });
    });
    const offset = el('input', { type: 'number', step: '0.001', value: String(h.offset_seconds || 0), style: 'width: 7em',
                                 title: 'Seconds to add to this host\'s event times, for example after finding clock drift' });
    offset.addEventListener('change', () => hostEdit({ host: h.host, offset_seconds: Number(offset.value) }));
    return el('tr', { class: h.review.length ? 'needs-review' : '', 'data-host': h.host },
              el('td', {}, h.host), roleCell, os, el('td', {}, review),
              el('td', {}, ...h.names.map((n) => ident(n, 'remove_name'))), el('td', {}, ...h.ips.map((i) => ident(i, 'remove_ip'))),
              el('td', {}, add), el('td', { class: 'nowrap' }, offset, ' s', ...clockCell(h)));
  }));
}

// Open the Hosts panel at one host's row, as "open the host's identity" from a lane label.
export function openHost(name) {
  $('hostsPanel').hidden = false;
  renderHosts();
  const row = [...$('hostsTable').querySelectorAll('tr[data-host]')].find((tr) => tr.dataset.host === name);
  if (!row) return;
  row.scrollIntoView({ block: 'nearest' });
  row.classList.add('flash');
  setTimeout(() => row.classList.remove('flash'), 1600);
}

// Counts the range reads asked for. A read can answer after a later change's read, and written, it would put back the
// range from before that change.
let rangeTurn = 0;

// The case's range and Fit case's, read again; the error, when the read failed. fit_range reads every event, so only a
// change that moves times asks for it. A read that a later one has replaced writes nothing and reports no error.
async function rereadRange() {
  const turn = ++rangeTurn;
  try {
    const { start, end, fit } = await api('/api/meta');
    if (turn !== rangeTurn) return null;
    Object.assign(S.meta, { start, end, fit });
    fitTitle();
    return null;
  } catch (err) { return turn === rangeTurn ? err : null; }
}

// Apply a host change's answer: the hosts, the lanes, the window's data, the counts, and the Event page of the event in
// focus, whose time and clock note follow an offset. The change is written once the server has answered, so a reload
// that fails doesn't fail it: the rest still follows, and the status line says what didn't reload. `done` is
// focusedPageAction() from before the change was asked for. Once the timeline has redrawn, the Event page of the event
// in focus reloads while the panel shows it and no page has been asked for since, as it may have read the time from
// before the change. The page the change was asked from counts from when the change was asked (pageAction); a page
// drawn while the change was out counts from when it drew (pageAnswered), whether it was asked for before the change,
// left and opened again, or another event's page. A page asked for since keeps the panel, and one still loading
// reloads as it draws. `moved` says the change moved times, as an offset, a split, or its undo does, since the new
// hosts don't take the old host's offset: then the case's range and Fit case's move with them, and To investigate,
// which lists the events in adjusted time order, draws again when it is on screen. Returns what didn't reload, for the
// status line, or ''.
export async function applyHosts(res, done, { moved = false } = {}) {
  S.meta.hosts = res.hosts;
  S.meta.outside_sources = res.outside_sources;
  S.meta.identity_conflicts = res.identity_conflicts;
  S.meta.clock_alignment = res.clock_alignment;
  S.meta.mixed = res.mixed;
  S.meta.splits = res.splits;
  S.meta.kept = res.kept;
  renderClockSwitch();
  if (!$('hostsPanel').hidden) renderHosts();
  const range = moved ? rereadRange() : null;
  let lanes = null;
  try { await reloadLanes(); } catch (err) { lanes = err; }
  const stale = await range;   // the view asks what lies outside Fit case's range, so it waits for the range
  await fetchView();
  refreshCounts();
  // The reload is awaited here, not left to the helper, so a control focused after an alignment is on the page it draws
  const unchanged = done(false);   // the page the change was asked from, with no page asked for since
  const page = `event:${S.focus}`;
  if (S.focus && (unchanged || pageAnswered(page, false)) && showingPage(page)) await settleRedraw(() => loadDetails(S.focus));
  if (moved) pageAnswered('investigate');   // the worklist lists the events in their adjusted time order
  const warning = lanes ? `The hosts changed, but the timeline didn't reload: ${lanes.message}`
    : stale ? `The hosts changed, but the case's range didn't reload: ${stale.message}` : '';
  if (warning) setStatus(warning);
  return warning;
}

export async function hostEdit(body) {
  const done = focusedPageAction();
  let res;
  try { res = await post('/api/host', body); } catch (err) { setStatus(`Host change failed: ${err.message}`); return; }
  await applyHosts(res, done, { moved: 'offset_seconds' in body });
}

export async function confirmRoles(names) {
  const done = focusedPageAction();
  let res;
  try { res = await post('/api/host', { confirm_hosts: names }); } catch (err) { setStatus(`Confirm failed: ${err.message}`); return; }
  await applyHosts(res, done);
}

// ---------- splitting a host by recorded computer ----------
// A notice above the hosts table for each host whose event logs record several computers, with a preview of the split;
// a line per host kept as one host, which can still be split; and a line per split host with Undo split. The numbers
// all come from the server. Each control that a change takes away hands the focus to the one that replaces it, as the
// clock's Align buttons do.

const listed = (names, shown = 3) => (names.length > shown
  ? `${names.slice(0, shown).join(', ')}, and ${names.length - shown} more` : names.join(', '));
// The control of one host's notice or line, found by data attributes, since a host folder's name can hold anything.
const splitControl = (host, role) => [...$('hostSplits').querySelectorAll(`[data-control="${role}"]`)]
  .find((b) => b.dataset.host === host);
const afterUndo = (host) => () => splitControl(host, 'open') || $('hostsButton');
// Every pivot but the logon session's searches the whole case; the time window's isn't a pivot button.
const CASE_WIDE = [...PIVOTS.filter(([kind]) => kind !== 'session').map(([, label]) => label), EITHER_END_PIVOT[1]];
const CASE_WIDE_TEXT = `${CASE_WIDE.slice(0, -1).join(', ')}, and ${CASE_WIDE[CASE_WIDE.length - 1]}`;

function renderSplits() {
  const box = $('hostSplits');
  $('hostsPanel').classList.remove('splitting');
  const notices = (S.meta.mixed || []).map((m) => {
    const role = m.role_source === 'guess' ? `one role guess (${m.role})` : `one role (${m.role})`;
    return offerSplit(m.host, 'split-notice',
      el('p', {}, el('strong', {}, `${m.host}'s event logs were recorded by ${m.computers} computers.`),
         ` They read as one machine: one lane, ${role}, ${plural(m.names, 'name')}, and logon-session and time-window ` +
         'pivots that join events across machines.' +
         (m.forwarded ? ` ${plural(m.forwarded, 'event')} came from forwarded events.` : '')),
      button(`Keep ${m.host} as one host`,
             () => changeSplit({ keep_host: m.host }, `Kept ${m.host} as one host`, afterUndo(m.host)),
             { title: 'Journal that these computers belong together; the notice comes back if another computer appears. ' +
                      'The host can still be split from its line here.' }));
  });
  // Kept as one host: the choice is journaled, and the split stays on offer while the logs record several computers.
  const kept = (S.meta.kept || []).map((k) => offerSplit(k.host, 'split-kept',
    el('p', {}, `${k.host} is kept as one host, though its event logs record ${k.computers} computers `,
       el('span', { class: 'muted' }, `(#${k.entry.seq}, ${k.entry.who}, ${fmtAt(k.entry.at)})`), '.')));
  const done = (S.meta.splits || []).map((s) => {
    const last = s.entries[s.entries.length - 1];
    // What the analyst set on the new hosts is journaled under their names, so it stops applying when they go.
    const edits = Object.entries(s.edits || {}).map(([lane, list]) => `${lane}, ${list.join('; ')}`);
    const opener = button('Undo split', () => {
      confirm.hidden = false;
      opener.setAttribute('aria-expanded', 'true');
      yes.focus();
    }, { 'aria-label': `Undo split of ${s.host}`, 'aria-expanded': 'false', 'data-control': 'undo', 'data-host': s.host });
    const yes = button('Confirm undo', () => changeSplit({ unsplit: s.host }, `Undid the split of ${s.host}`, afterUndo(s.host)),
                       { class: 'primary', 'aria-label': `Confirm undo split of ${s.host}` });
    const confirm = el('div', { class: 'split-confirm', hidden: '' },
      el('p', {}, `Undo the split of ${s.host}? Its event logs go back to ${s.host}'s lane. Every event keeps its ID, ` +
                  'marks, notes, and tags, and the journal records the undo.'),
      ...(edits.length ? [el('p', {}, 'What you set on the new hosts stops applying, and applies again if a later split ' +
                                      `makes the same host: ${edits.join('. ')}.`)] : []),
      el('div', { class: 'actions' }, yes,
        button('Cancel', () => { confirm.hidden = true; opener.setAttribute('aria-expanded', 'false'); opener.focus(); })));
    return el('div', { class: 'split-done', 'data-host': s.host },
      el('span', {}, `${s.host} is split by recorded computer into ${plural(s.lanes.length, 'new host')}: ${listed(s.lanes, 6)}`),
      el('span', { class: 'muted' }, ` (#${s.entries.map((e) => e.seq).join(', #')}, ${last.who}, ${fmtAt(last.at)})`), ' ',
      opener, confirm);
  });
  box.replaceChildren(...notices, ...kept, ...done);
  box.hidden = !notices.length && !kept.length && !done.length;
}

// A notice or a kept host's line: its text, Split HOST by recorded computer…, any other buttons, and the preview's box.
function offerSplit(host, kind, text, ...more) {
  const preview = el('div', { class: 'split-preview', hidden: '' });
  const open = button(`Split ${host} by recorded computer…`, () => previewSplit(host, preview, open),
                      { class: 'primary', 'aria-expanded': 'false', 'data-control': 'open', 'data-host': host });
  return el('div', { class: kind, 'data-host': host }, text, el('div', { class: 'actions' }, open, ...more), preview);
}

async function previewSplit(host, box, opener) {
  const close = () => {
    box.hidden = true;
    opener.setAttribute('aria-expanded', 'false');
    $('hostsPanel').classList.remove('splitting');
  };
  if (!box.hidden) { close(); return; }   // the opener toggles its preview
  let p;
  try { p = await api(`/api/host_split?host=${encodeURIComponent(host)}`); }
  catch (err) { box.replaceChildren(el('p', {}, err.message)); box.hidden = false; return; }
  const number = (n) => el('td', { class: 'num' }, n.toLocaleString());
  const table = el('table', { class: 'split-table' },
    el('thead', {}, el('tr', {}, ...['New host', 'Recorded as', 'Event log events', 'Hayabusa rows', 'Files']
      .map((h, i) => el('th', { class: i > 1 ? 'num' : '' }, h)))),
    el('tbody', {}, ...p.groups.map((g) => el('tr', {},
      el('td', {}, g.lane, ...(g.note ? [el('div', { class: 'muted' }, `Renamed: ${g.note}`)] : [])),
      el('td', {}, listed(g.names)), number(g.events), number(g.hayabusa), number(g.files)))));
  const happens = [
    // What the evidence allows, said plainly: a split moves event logs only, and those give no OS or IP address.
    'Each new host gets its own lane, role guess, and names, and an OS and a clock check where its evidence allows. ' +
      'Event logs alone give neither, so the new hosts show OS Not recorded and no clock check.',
    // Only these two pivots read the host; the IP pivots and the rest are case-wide by design.
    `The logon-session and time-window pivots stay within one machine. ${CASE_WIDE_TEXT} search ` +
      'the whole case, as they always do.',
    `Marks, notes, and tags move with their events${refs(p.moving)}. The split is a journal entry, so the audit trail ` +
      `shows it, and Undo split on the Hosts panel puts ${host} back.`,
    stays(host, p.stays),
    ...(p.edits.length ? [`What you set for ${host} stays with it and doesn't reach the new hosts: ${p.edits.join('; ')}.`] : []),
  ];
  const heading = el('h3', { tabindex: '-1' }, `Split ${host} into ${plural(p.hosts_after, 'host')}`);
  box.replaceChildren(
    heading,
    // A Hayabusa row goes by the Computer it records, which is its event's: both read the record's System element.
    el('p', {}, 'Each event goes to the computer it records, and each Hayabusa row with it.'),
    table,
    el('h4', {}, 'What happens'),
    el('ul', {}, ...happens.map((t) => el('li', {}, t))),
    el('div', { class: 'actions' },
      button(`Split into ${plural(p.hosts_after, 'host')}`,
             () => changeSplit({ split: host, basis: p.basis }, `Split ${host} into ${plural(p.groups.length, 'new host')}`,
                               () => splitControl(host, 'undo') || $('hostsButton')),
             { class: 'primary' }),
      button('Cancel', () => { close(); opener.focus(); })));
  box.hidden = false;
  opener.setAttribute('aria-expanded', 'true');
  // The panel is short so the timeline keeps its room; while a preview is open it takes more, the preview scrolls into
  // view, and its buttons stay at the panel's foot, where a preview of 11 computers would otherwise push them out of sight.
  $('hostsPanel').classList.add('splitting');
  heading.focus({ preventScroll: true });
  box.scrollIntoView({ block: 'nearest' });
}

function refs(m) {
  const parts = [m.marks && plural(m.marks, 'marked event'), m.notes && `${plural(m.notes, 'event')} with notes`,
                 m.tags && plural(m.tags, 'tagged event')].filter(Boolean);
  return parts.length ? `: ${parts.join(', ')} here, each keeping its ID` : '';
}

function stays(host, s) {
  const computers = s.computers.map((c) => `${listed(c.names, 2)} (${plural(c.events, 'event')}) stays on ${host}: ` +
                                            `it has ${c.reason}.`);
  const other = s.rows.filter((r) => !['evtx', 'hayabusa'].includes(r.artifact));
  const hits = s.rows.filter((r) => r.artifact === 'hayabusa').reduce((n, r) => n + r.count, 0);
  const words = other.map((r) => plural(r.count, `${artifactName(r.artifact)} event`));
  const lines = [...computers,
    words.length ? `Evidence that isn't an event log stays on ${host}: ${words.join(', ')}.`
                 : `Evidence that isn't an event log (an MFT, a hive) stays on ${host}; none here.`];
  if (hits && !s.computers.length) lines.push(`${plural(hits, 'Hayabusa row')} that record${hits === 1 ? 's' : ''} no computer stay${hits === 1 ? 's' : ''} on ${host}.`);
  return lines.join(' ');
}

// A split, its undo, or a keep. A View value or Sources rule naming a host that's gone would match nothing, and a
// Show only on it would hide everything, so they go. The filter is registered again whenever one is in force or a rule
// went: a split drops the case's saved searches, which a View value can hold, and a filter whose last rule went would
// still name the host that's gone. `target` gives the control to focus once the panel is drawn again, since the
// clicked one is gone.
async function changeSplit(body, done, target) {
  const settle = focusedPageAction();
  let res;
  try { res = await post('/api/host', body); }
  catch (err) { setStatus(`Host change failed: ${err.message}`); return; }
  const known = new Set(res.hosts.map((h) => h.host));
  const gone = (p) => 'host' in p && !known.has(p.host);
  let dropped = dropGoneHosts(known);
  for (const kind of ['only', 'hide', 'show']) {
    dropped += S.filter[kind].filter(gone).length;
    S.filter[kind] = S.filter[kind].filter((p) => !gone(p));
  }
  S.sources = null;   // its hosts and files are by lane
  let warning = await applyHosts(res, settle, { moved: !('keep_host' in body) });
  try {
    if (S.filterId || dropped || filterCount() || S.viewSpec) await applyFilter(); else renderFilterState();
    if (!$('filterPanel').hidden) await toggleFilterPanel(true);   // counts the sources again, by the new lanes
  } catch (err) { if (!warning) warning = `The hosts changed, but the timeline didn't reload: ${err.message}`; }
  setStatus(done + (dropped ? `; ${plural(dropped, 'filter value')} naming a host that's gone came off` : '') +
            (warning ? `. ${warning}` : ''));
  refocus(target);
}

// The right-click menu on a host or role lane label: confirm or change the role, or open the host in the Hosts panel.
// The right-click menu on a lane label: Show only, Hide, and the categories inside the lane, plus,
// on host and role labels, confirming or changing roles and opening hosts.
export function openLaneMenu(row, x, y) {
  const pred = { [row.key]: row.label };
  const hosts = ['host', 'role'].includes(row.key) ? hostsUnder(row).map(hostInfo).filter(Boolean) : [];
  const extra = [];
  let title = `${KEY_LABEL[row.key]}: ${row.label}`, subtitle = '';
  if (row.key === 'host' && hosts[0]) {
    const h = hosts[0];
    title = `${h.host}: ${h.role}`;
    subtitle = roleStatus(h);
    const role = h.role_source === 'guess' ? [menuItem(`Confirm ${h.role}`, () => confirmRoles([h.host]))] : [];
    for (const r of ROLES.filter((x2) => x2 !== h.role)) role.push(menuItem(`Change role to ${r}`, () => hostEdit({ host: h.host, role: r })));
    extra.push(role, [menuItem('Open in the Hosts panel', () => openHost(h.host))]);
  } else if (row.key === 'role' && hosts.length) {
    const guessed = hosts.filter((h) => h.role_source === 'guess');
    subtitle = `${plural(hosts.length, 'host')}, ${guessed.length} with a guessed role`;
    if (guessed.length) {
      extra.push([menuItem(guessed.length === 1 ? `Confirm ${row.label} for ${guessed[0].host}`
                                                : `Confirm ${row.label} for ${guessed.length} guessed hosts`,
                           () => confirmRoles(guessed.map((h) => h.host)))]);
    }
    extra.push(hosts.slice(0, 12).map((h) => menuItem(`Open ${h.host} in the Hosts panel`, () => openHost(h.host))));
  }
  openItemMenu(pred, x, y, { title, subtitle, extra });
}
