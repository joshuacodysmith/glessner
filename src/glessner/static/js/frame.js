// The Case panel, grouped by job: the case's name with its state under it, the triage path (Overview,
// Timeline, To investigate, Findings, Audit trail), and the Case menu, which holds the setup and record work. Every control the
// panel had before is still here, in the Case menu, or in the Timeline's own toolbar. The Case menu's Export opens the
// Findings page, whose right column holds the export controls.

import { showAudit } from './audit.js';
import { $, api, HINTS, plural, S } from './core.js';
import { loadDetails, setPage } from './event_page.js';
import { showFindings } from './findings.js';
import { renderHosts } from './hosts.js';
import { showImport } from './import.js';
import { showOverview } from './overview.js';
import { showInvestigate, showRules } from './pages.js';
import { showTools } from './tools.js';

// Controls whose hover text other modules write, with live detail after the hint
const LIVE_TITLES = new Set(['fit', 'filtersButton', 'viewButton', 'investigateButton', 'hostsButton', 'rulesButton',
                             'caseMenuButton']);
let hint = null;   // the Details panel's opening hint, which the Timeline step shows when no event is in focus
let behind = false;   // a page is being drawn behind the overview (behindOverview)

export function setupFrame() {
  for (const [id, text] of Object.entries(HINTS)) {
    const node = $(id);
    if (node && !LIVE_TITLES.has(id)) node.title = text;
  }
  const first = $('details').querySelector('.hint');
  hint = first ? first.cloneNode(true) : null;
  $('tabOverview').addEventListener('click', () => showTab('overview'));
  $('tabTimeline').addEventListener('click', () => showTab('timeline'));
  $('investigateButton').addEventListener('click', () => showTab('investigate'));
  $('tabFindings').addEventListener('click', () => showTab('findings'));
  $('tabAudit').addEventListener('click', () => showTab('audit'));
  setupCaseMenu();
  renderCaseState(S.meta.case_state);
}

// Show a step of the path. The overview lies over the timeline and the Details panel, which stay laid out and loaded
// behind it, so leaving it is instant; while it shows, they are inert, out of the keyboard's reach. The path lights the
// step the Details panel's page belongs to (followPage), so the Timeline step takes the panel off To investigate or the
// Findings page, back to the event in focus or the opening hint.
export function showTab(name) {
  const overview = name === 'overview';
  $('overview').hidden = !overview;
  for (const id of ['work', 'divider', 'details']) $(id).inert = overview;
  markTab(name);
  if (overview) return showOverview();   // as the case opens, the timeline waits for it
  if (name === 'investigate') showInvestigate();
  else if (name === 'findings') showFindings();   // the findings, with the exports beside them
  else if (name === 'audit') showAudit();   // the Case menu's entry opens it too
  else if (['investigate', 'findings', 'audit'].includes($('details').dataset.page)) {
    if (S.focus) loadDetails(S.focus);
    else showHint();
  }
}

// The Details panel's opening page, for when no event is in focus: the Timeline step with nothing selected, and a
// shift-click that took the last event out of the selection. An event page still loading for one is
// dropped, since loadDetails draws only the focused event.
export function showHint() {
  setPage('hint', hint ? [hint.cloneNode(true)] : []);
}

export function markTab(name) {
  S.tab = name;
  for (const b of $('path').querySelectorAll('button')) {
    if (b.dataset.tab === name) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  }
}

// The path follows the Details panel: To investigate, the Findings page, and the audit trail light their steps, and any other page is
// the Timeline's. A page opened while the overview shows, such as a search or the Tools page from the Case menu, brings
// the timeline and the Details panel forward, except one drawn behindOverview.
export function followPage(page) {
  if (behind) return;
  if (!$('overview').hidden) {
    $('overview').hidden = true;
    for (const id of ['work', 'divider', 'details']) $(id).inert = false;
  }
  markTab(['investigate', 'findings', 'audit'].includes(page) ? page : 'timeline');
}

// Draw the Details panel's page behind the overview, which stays up with its step lit: a reload on the overview puts back
// the page the Timeline step then shows. `draw` is awaited whole, so no page lands after it.
export async function behindOverview(draw) {
  behind = true;
  try { await draw(); } finally { behind = false; }
}

// A menu button (WAI-ARIA's pattern): Enter, Space, or a click opens it at its first item, and the arrow down or up key
// at its first or last; the arrow keys, Home, and End move; Escape closes it and gives the focus back to the button;
// Tab, a click elsewhere, or the focus leaving it any other way, such as by the / key, closes it.
function setupCaseMenu() {
  const button = $('caseMenuButton'), menu = $('caseMenu'), box = $('caseMenuBox');
  const items = () => [...menu.querySelectorAll('[role="menuitem"]')];
  const open = (at) => {
    menu.hidden = false;
    button.setAttribute('aria-expanded', 'true');
    const list = items();
    list[(at + list.length) % list.length].focus();
  };
  const close = (focusButton = true) => {
    if (menu.hidden) return;
    menu.hidden = true;
    button.setAttribute('aria-expanded', 'false');
    if (focusButton) button.focus();
  };
  button.addEventListener('click', () => (menu.hidden ? open(0) : close()));
  button.addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowDown' && ev.key !== 'ArrowUp') return;
    ev.preventDefault();
    open(ev.key === 'ArrowDown' ? 0 : -1);
  });
  menu.addEventListener('keydown', (ev) => {
    const list = items(), at = list.indexOf(document.activeElement);
    if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
      list[(at + (ev.key === 'ArrowDown' ? 1 : -1) + list.length) % list.length].focus();
    } else if (ev.key === 'Home' || ev.key === 'End') {
      list[ev.key === 'Home' ? 0 : list.length - 1].focus();
    } else if (ev.key === 'Escape') {
      close();
    } else {
      if (ev.key === 'Tab') close(false);
      return;
    }
    ev.preventDefault();
    ev.stopPropagation();
  });
  document.addEventListener('mousedown', (ev) => { if (!menu.hidden && !box.contains(ev.target)) close(false); });
  box.addEventListener('focusout', (ev) => { if (ev.relatedTarget && !box.contains(ev.relatedTarget)) close(false); });
  const item = (id, action) => $(id).addEventListener('click', () => { close(); action(); });
  item('hostsButton', () => { const p = $('hostsPanel'); p.hidden = !p.hidden; renderHosts(); });
  item('toolsButton', () => showTools());
  item('importButton', () => showImport());
  item('rulesButton', () => showRules());
  item('exportButton', () => showTab('findings'));   // the exports sit on the Findings page
  item('auditButton', () => showTab('audit'));
  item('casesButton', () => { location.href = '/start'; });
}

// The line under the case's name: open or closed, the evidence against intake, and the analyst. The evidence part
// reads every check verification.jsonl records (intake.evidence_checks): each run re-hashes the files it read, and the
// report, verify, and a close re-hash all. A problem stays until a later full re-hash matches, and a close
// shows beside it, never in its place. A file a check couldn't read is counted apart from a changed one, since no hash
// was compared, and a line of the log that can't be read is a warning on any state, since it may have held a problem.
export function renderCaseState(st) {
  if (!st) return;
  const day = (iso) => String(iso || '').slice(0, 10);
  const warn = (text) => {
    const span = document.createElement('span');
    span.className = 'warn';
    span.textContent = text;
    return span;
  };
  const ev = st.checks || {};
  const parts = [document.createTextNode(st.closed ? `Closed on ${day(st.closed.at)}` : 'Open')];
  let title = st.intake
    ? `${plural(st.evidence_files, 'evidence file')} hashed at intake (SHA-256)` +
      (st.added_files ? `, and ${st.added_files.toLocaleString()} added later` : '') +
      (st.unreadable ? `; ${plural(st.unreadable, 'file')} intake could not read` : '') +
      (st.unlisted ? `; ${plural(st.unlisted, 'folder')} intake could not list` : '') + '.'
    : 'No intake manifest: the evidence was not hashed.';
  const evidence = document.createElement('span');
  if (!st.intake) {
    evidence.append('no intake manifest yet');
  } else if (ev.files) {
    const found = [ev.changed_files ? `evidence changed since intake: ${plural(ev.changed_files, 'file')}` : '',
                   ev.not_reread ? `${plural(ev.not_reread, 'evidence file')} could not be re-read` : ''];
    evidence.append(warn(found.filter(Boolean).join('; ')));
    title += ` Found by the evidence checks since the last full re-hash that matched, the newest on ${day(ev.found_at)}: ` +
             `${ev.problems.slice(0, 10).join('; ')}${ev.problems.length > 10 ? `; and ${ev.problems.length - 10} more` : ''}.`;
    if (ev.not_reread) {
      title += ' A check that could not read a file, as when another program holds it open, compared no hash; a full ' +
               're-hash that matches, such as the verify command\'s, clears it.';
    }
  } else if (ev.last_full) {
    // A file intake couldn't read has no hash, so no re-hash checked it, nor the files of a folder it couldn't list,
    // which are counted as a folder since how many there are is unknown. The line says so, as its hover does.
    evidence.append(`full re-hash matched on ${day(ev.last_full.at)}`);
    if (st.unreadable) evidence.append('; ', warn(`${plural(st.unreadable, 'file')} unverified`));
    if (st.unlisted) evidence.append('; ', warn(`${plural(st.unlisted, 'folder')} unverified`));
  } else {
    evidence.append(ev.newest ? "runs' evidence checks matched; no full re-hash yet" : 'evidence not re-checked since intake');
  }
  if (st.intake && ev.unreadable_lines) {
    const n = ev.unreadable_lines;
    evidence.append('; ', warn(`${plural(n, 'check-log line')} unreadable`));
    title += ` ${plural(n, 'line')} of verification.jsonl could not be read, so any problem ` +
             `${n === 1 ? 'it holds' : 'they hold'} is not counted here.`;
  }
  parts.push(evidence);
  if (ev.newest) {
    const n = ev.newest;
    title += ` The newest check, ${n.at} (${n.reason || 'no reason given'}), listed ${plural(n.files_checked, 'file')}: ` +
             `${n.result === 'ok' ? 'every readable one matched' : plural(n.problems, 'problem')}.`;
  }
  if (S.meta.analyst) parts.push(document.createTextNode(`analyst ${S.meta.analyst}`));
  // "Journal changed" in red, only while the chain is broken; otherwise the line is unchanged
  S.journal = st.journal || null;
  if (st.journal?.broken) {
    const changed = document.createElement('span');
    changed.className = 'warn journal-changed';
    changed.textContent = 'Journal changed';
    parts.splice(1, 0, changed);   // after Open or Closed
    title += ` ${st.journal.read_only}`;
  }
  const line = $('caseState');
  line.replaceChildren(...parts.flatMap((p, i) => (i ? [document.createTextNode(' · '), p] : [p])));
  line.title = `${line.textContent}
${title}`;   // the line ellipsizes in a narrow header, so its hover holds all of it
}

// Read the case state again, after something that may have checked the evidence or closed the case
export async function refreshCaseState() {
  try { renderCaseState(await api('/api/case_state')); } catch (_) { /* the line keeps what it said */ }
}
