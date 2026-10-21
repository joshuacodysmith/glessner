// The audit trail: every journal entry in plain words, newest first, with undo for
// accidents. An undo adds a correction entry and never rewrites the journal; what changed after the undone entry
// keeps its later state. Notes are retracted rather than undone, and stay on record.

import { $, api, codePrefix, el, fmtUs, markBadge, plural, post, S, setStatus } from './core.js';
import { refreshCounts } from './counts.js';
import { fetchView } from './data.js';
import { button, claimDetails, headAfter, headCopy, loadDetails, setPage, showingPage } from './event_page.js';
import { renderHosts } from './hosts.js';
import { reloadLanes } from './lanes.js';
import { jumpTo, showRules } from './pages.js';

const PANEL_OPEN = { hosts: () => { const p = $('hostsPanel'); p.hidden = false; renderHosts(); }, rules: () => showRules() };

export async function showAudit(filters = {}) {
  const params = new URLSearchParams({ ...filters, limit: '200' });
  const latest = claimDetails();   // a page asked for after it keeps the panel
  let res;
  try { res = await api(`/api/audit?${params}`); }
  catch (err) { setStatus(`Audit trail failed: ${err.message}`); return; }
  if (!latest()) return;
  const page = { key: 'audit', title: 'Audit trail', reopen: () => showAudit(filters) };
  const refilter = (change) => showAudit(Object.fromEntries(Object.entries({ ...filters, ...change }).filter(([, v]) => v)));
  const kind = el('select', { 'aria-label': 'Action' }, el('option', { value: '' }, 'All actions'),
                  ...res.kinds.map((k) => el('option', { value: k }, k)));
  kind.value = filters.kind || '';
  kind.addEventListener('change', () => refilter({ kind: kind.value }));
  const who = el('select', { 'aria-label': 'Analyst' }, el('option', { value: '' }, 'All analysts'),
                 ...res.analysts.map((a) => el('option', { value: a }, a)));
  who.value = filters.who || '';
  who.addEventListener('change', () => refilter({ who: who.value }));
  const q = el('input', { type: 'search', placeholder: 'Search the trail', 'aria-label': 'Search the trail', value: filters.q || '' });
  q.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') refilter({ q: q.value.trim() }); });
  const corr = el('input', { type: 'checkbox' });
  corr.checked = filters.corrections === '1';
  corr.addEventListener('change', () => refilter({ corrections: corr.checked ? '1' : '' }));
  const exported = el('p', { class: 'muted', hidden: '' });
  const exportButton = button('Export (Markdown)', async () => {
    try {
      const out = await post('/api/audit_export', {});
      const text = `Wrote ${plural(out.entries, 'entry', 'entries')} to ${out.path}.`;
      setStatus(text);
      exported.replaceChildren(text, headAfter(out));   // the head after its file entry, with Copy
      exported.hidden = false;
    } catch (err) { setStatus(`Export failed: ${err.message}`); }
  });
  // The chain's state, in Integrity's words, and the head of the read the trail lists
  const j = res.journal;
  const chain = j ? [el('p', { class: `audit-journal ${j.state}` }, el('span', { class: j.state === 'broken' ? 'warn' : '' }, j.text[0]),
    ` ${j.text.slice(1).join(' ')} Head `, ...headCopy(j.head, j.short), j.seq != null ? ` (entry #${j.seq}).` : '')] : [];
  const list = el('div', { class: 'audit-list' }, ...res.rows.map((r) => auditRow(r, filters)));
  setPage('audit', [
    ...chain,
    el('div', { class: 'actions' }, el('span', { class: 'muted' }, `${plural(res.total, 'entry', 'entries')}, newest first`),
       kind, who, q, el('label', {}, corr, ' Corrections only'), exportButton),
    exported,
    ...(filters.event ? [el('div', { class: 'fchips' }, el('span', { class: 'fchip' }, 'Only entries for one event',
         button('×', () => refilter({ event: '' }), { 'aria-label': 'Show every entry' })))] : []),
    // This ID names a loaded event, and an upgrade also moved it to another, whose entries these aren't
    ...(res.id_also_named ? [el('p', { class: 'muted id-also-named' },
      `Before the case format upgrade at ${res.id_also_named.seqs.map((s) => `#${s}`).join(' and ')}, this ID named ` +
      `another event, which has the ID ${res.id_also_named.now} now; the entries made under this ID before then are ` +
      'listed under that one. ',
      button("Show that event's entries", () => refilter({ event: res.id_also_named.now }), { class: 'linklike' }))] : []),
    el('p', { class: 'muted' }, 'Undo is for accidents: it adds a correction and keeps the original entry. ' +
       'To change a verdict on the evidence, mark or tag the events again.'),
    res.rows.length ? list : el('p', {}, 'No entry matches.'),
    ...(res.total > res.rows.length ? [el('p', { class: 'muted' }, `Showing the newest ${res.rows.length} of ${res.total.toLocaleString()}. Narrow the filters to see others.`)] : []),
  ], page);
}

// An entry's words, with the one event it names quoted and cut at a word or address boundary (the server's cut_name): the
// whole name and the event's time in its hover, and a click that opens the event. The mark word or the note
// then reads apart from the name. An entry naming no single event, or whose name the words don't hold, is plain text.
function entryText(r) {
  const ev = r.event;
  const at = ev ? r.text.indexOf(ev.name) : -1;
  if (!ev || at < 0) return [r.text];
  const open = button(`“${ev.short}”`, () => jumpTo(ev), {
    class: 'linklike ev-name', title: `${fmtUs(ev.ts)}${ev.ts == null ? '' : ' UTC'}\n${ev.name}\nClick to open the event` });
  return [r.text.slice(0, at), open, r.text.slice(at + ev.name.length)];
}

function auditRow(r, filters) {
  const when = `${String(r.at).slice(5, 16).replace('T', ' ')} UTC`;
  const undone = r.undone_by != null;
  const text = el('span', { class: undone || r.retracted_by ? 'gone' : '' }, ...entryText(r));
  const badges = [];
  if (r.action === 'undo') badges.push(el('span', { class: 'correction-tag' }, 'correction: accident'));
  if (undone) badges.push(el('span', { class: 'muted' }, ` Undone by #${r.undone_by}`));
  if (r.retracted_by) badges.push(el('span', { class: 'muted' }, ` Retracted by #${r.retracted_by}`));
  // Read through a case format upgrade that changed event IDs: why an ID differs from the journal's line
  if (r.rekeyed) badges.push(el('span', { class: 'muted' }, ` ${r.rekeyed}`));
  const confirmBox = el('div', { class: 'audit-confirm', hidden: '' });
  const actions = [];
  if (r.count > 1) actions.push(button(`${r.count.toLocaleString()} events`, () => toggleEvents(r.seq, confirmBox), { class: 'linklike' }));
  if (r.undoable) actions.push(button('Undo', () => confirmUndo(r, confirmBox, filters)));
  if (r.action === 'note' && !r.retracted_by) actions.push(button('Retract', () => confirmRetract(r, confirmBox, filters)));
  if (r.panel && PANEL_OPEN[r.panel]) actions.push(button(r.panel === 'hosts' ? 'Change it in Hosts' : 'Change it in Rules', PANEL_OPEN[r.panel], { class: 'linklike' }));
  return el('div', { class: `audit-row${r.action === 'undo' ? ' correction' : ''}` },
    el('span', { class: `seq${undone ? ' gone' : ''}` }, `#${r.seq}`), el('span', { class: 'muted' }, when), el('span', {}, r.who),
    el('span', {}, text, ...badges), el('span', { class: 'audit-actions' }, ...actions), confirmBox);
}

async function toggleEvents(seq, box) {
  if (!box.hidden && box.dataset.kind === 'events') { box.hidden = true; return; }
  let res;
  try { res = await api(`/api/audit_events?seq=${seq}`); } catch (err) { setStatus(err.message); return; }
  box.dataset.kind = 'events';
  box.replaceChildren(el('ul', { class: 'related badged' }, ...res.events.map((e) => el('li', { onclick: () => jumpTo(e) },
    markBadge(e), el('span', {}, `${fmtUs(e.ts)}  ${e.host}  ${codePrefix(e)}${e.msg}`)))),
    ...(res.total > res.events.length ? [el('p', { class: 'muted' }, `The first ${res.events.length} of ${res.total.toLocaleString()} in time order.`)] : []));
  box.hidden = false;
}

async function confirmUndo(r, box, filters) {
  let plan;
  try { plan = await api(`/api/undo_plan?seq=${r.seq}`); }
  catch (err) { box.dataset.kind = 'confirm'; box.replaceChildren(el('p', {}, err.message)); box.hidden = false; return; }
  const note = el('input', { type: 'text', class: 'mark-note', placeholder: 'Note (optional), such as what went wrong' });
  const n = (k) => plural(k, 'event');
  const back = plan.changed === 1 ? 'back to how it was' : 'back to how they were';
  const explain = plan.changed
    ? `${n(plan.changed)} ${plan.changed === 1 ? 'goes' : 'go'} ${back} before #${r.seq}.` +
      (plan.kept ? ` ${n(plan.kept)} changed after #${r.seq} and ${plan.kept === 1 ? 'keeps its' : 'keep their'} later state.` : '')
    : `Nothing left to undo: every event in #${r.seq} changed after it.`;
  box.dataset.kind = 'confirm';
  box.replaceChildren(
    el('strong', {}, `Undo #${r.seq}?`), el('div', {}, plan.text),
    el('p', { class: 'muted' }, `${explain} The original entry stays in the journal; this adds a correction of an accident.`),
    ...(plan.changed ? [el('div', { class: 'actions' }, note,
      button(`Undo ${n(plan.changed)}`, async () => {
        try { await post('/api/undo', { seq: r.seq, note: note.value }); }
        catch (err) { setStatus(`Undo failed: ${err.message}`); return; }
        setStatus(`Undid #${r.seq}: ${n(plan.changed)} ${back}`);
        await afterChange();
        if (showingPage('audit')) showAudit(filters);   // not over a page asked for meanwhile
      }, { class: 'undo' }),
      button('Cancel', () => { box.hidden = true; }))] : [button('Close', () => { box.hidden = true; })]));
  box.hidden = false;
  note.focus();
}

function confirmRetract(r, box, filters) {
  box.dataset.kind = 'confirm';
  box.replaceChildren(el('strong', {}, `Retract note #${r.seq}?`),
    el('p', { class: 'muted' }, 'The note stays on record, struck through, with who retracted it and when.'),
    el('div', { class: 'actions' }, button('Retract', async () => {
      const uid = await noteTarget(r.seq);
      try { await post('/api/note_retract', { uid, note_seq: r.seq }); }
      catch (err) { setStatus(`Retract failed: ${err.message}`); return; }
      await afterChange();
      if (showingPage('audit')) showAudit(filters);
    }, { class: 'undo' }), button('Cancel', () => { box.hidden = true; })));
  box.hidden = false;
}

async function noteTarget(seq) {
  const res = await api(`/api/audit_events?seq=${seq}`);
  return res.events.length ? res.events[0].uid : '';
}

export async function retractNote(uid, noteSeq) {
  try { await post('/api/note_retract', { uid, note_seq: noteSeq }); }
  catch (err) { setStatus(`Retract failed: ${err.message}`); return; }
  setStatus(`Retracted note #${noteSeq}`);
  loadDetails(uid);
}

// The timeline and counts follow an undo or retraction. The Details panel stays on the trail, which redraws itself;
// reloading the focused event here as well raced it for the panel.
async function afterChange() {
  await reloadLanes();
  await fetchView();
  refreshCounts();
}

// The Event page's History: the newest entries for this event, with a way into the full trail. Returns the rows, so the
// page's fold can say how many; HISTORY_LIMIT of them means there may be more.
export const HISTORY_LIMIT = 30;
export async function loadHistory(uid, box) {
  let res;
  try { res = await api(`/api/audit?event=${encodeURIComponent(uid)}&limit=${HISTORY_LIMIT}`); } catch (_) { return null; }
  if (S.focus !== uid) return null;
  box.replaceChildren(
    ...(res.rows.length ? [el('ul', { class: 'history' }, ...res.rows.map((r) => el('li', { class: r.undone_by != null || r.retracted_by ? 'gone' : '' },
      el('span', { class: 'seq' }, `#${r.seq}`), ` ${r.text}, ${r.who}, ${String(r.at).slice(5, 16).replace('T', ' ')}`,
      ...(r.rekeyed ? [el('span', { class: 'muted' }, ` (${r.rekeyed})`)] : []))))]
      : [el('p', { class: 'muted' }, 'Nothing recorded for this event yet.')]),
    button('Open in the audit trail', () => showAudit({ event: uid }), { class: 'linklike' }));
  return res.rows;
}
