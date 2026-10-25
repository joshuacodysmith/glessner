import { attackField, attackList } from './attack.js';
import { askSelection, CONFIRM_ABOVE } from './confirm.js';
import { $, api, codePrefix, el, fmtAt, fmtUs, markBadge, plural, post, reportAction, S, setStatus } from './core.js';
import { artifactName, button, claimDetails, fold, loadDetails, pageAction, pageRead, readOnlyHint, setPage } from './event_page.js';
import { exportsColumn, summaryDraft } from './exports.js';
import { markableList } from './pages.js';

// ---------- Findings ----------
// The Findings tab's page: the analyst's findings on the left, the report, the exports, and the files written on the right
// (exports.js; one column below 960 px). A finding is a conclusion the analyst writes and the journal records (title,
// severity, narrative, ATT&CK techniques, and the events that support it); the app never writes one or its words. Each
// card shows its severity as a worded chip, never a mark's letter or fill, its linked events as chips that open them, each
// with its current mark, and the caveats from those events' types. Edit, link, unlink, retire, and restore go through
// /api/finding; a link or a new finding of more than CONFIRM_ABOVE events asks first. Evidence text reaches the page
// through el() only.

export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
export const CAVEAT_OPEN_KEY = 'glessner.caveatOpen';   // per-browser: whether the Event page's caveat starts open
const CHIPS = 8;                                        // event chips a card shows before "+N more"
const PAGE = 'findings';
const FIELDS = ['title', 'severity', 'narrative', 'techniques'];   // what a finding form edits, in the order a status line names them
const pickFields = (v) => Object.fromEntries(FIELDS.map((k) => [k, v[k]]));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

let titles = null;   // the open findings' numbers and titles, for the Event page's picker; cleared by every write
const drafts = new WeakMap();   // each open finding form's node: how to read its fields as a draft
const saving = new WeakSet();   // the finding forms whose write is out
let unshown = null;   // the draft a reload kept that no Findings page has drawn since
// The list of marked events in no finding, as a redraw after a change on the page keeps it: whether it is open, and its
// ticks, which also hold its note (pages.markableList)
let unfiled = { open: false, checked: new Set() };

// Keep the draft findingsDraft gave before a reload for the next draw of the Findings page, whichever page the reload
// draws: the Findings page, whose read can fail, or another, which may be the path's step or a page asked for first.
export function keepFindingsDraft(draft) {
  unshown = draft;
}

// Draw the page. `newFrom` opens the new-finding form over these events, as "New finding" from the Event page does; a
// new finding's form a reload kept gives it its words. `keep` draws the page again after a change made on it, with what
// is open on it as it is: the forms less one whose change was saved, the retire reasons, the Summary's unsaved text, the
// field with the focus and its caret, and the list of marked events in no finding with its ticks and note.
// A draft a reload kept opens with the page: its forms as they were, and the Summary with its text. An edit form shows the
// finding's current value for a field the finding has changed since the form opened and the form left alone (findingForm).
// Until the page draws, the draft stays kept, across further reloads too. An edit form whose finding has been retired
// since can't open again, and the status line says so. Returns how many couldn't.
export async function showFindings({ newFrom = null, keep = false } = {}) {
  const latest = claimDetails();
  const drew = pageRead();
  let res;
  try { res = await api('/api/findings_page'); }
  catch (err) {
    const kept = 'The open finding forms and the Summary\'s unsaved text are kept until the page loads.';
    if (latest()) {
      if (keep) unshown = joinDrafts(unshown, pageDraft({ settled: true }));
      setPage(PAGE, [el('p', { class: 'pad' }, `Could not load the findings: ${err.message}`),
                     ...(unshown ? [el('p', { class: 'pad' }, kept)] : [])]);
    }
    return 0;
  }
  if (!latest()) return 0;
  attackList().catch(() => {});   // the ATT&CK field's list, read before a form opens; a form says so if it fails
  titles = res.findings.filter((f) => !f.retired).map((f) => ({ id: f.id, number: f.number, title: f.title }));
  const open = res.findings.filter((f) => !f.retired), retired = res.findings.filter((f) => f.retired);
  const focus = keep ? focusedField() : null;
  const kept = keptDraft(joinDrafts(unshown, keep ? pageDraft({ settled: true }) : null));
  unshown = null;
  if (!keep) unfiled = { open: false, checked: new Set() };
  const left = el('section', { class: 'findings-col' });
  const slot = el('div', { class: 'confirm-slot' });
  const form = el('div', { class: 'finding-new' });
  const closeForm = () => form.replaceChildren();
  const openForm = (targets, draft = null) => {
    form.replaceChildren(findingForm({ targets, slot, onCancel: closeForm, draft }));
    form.querySelector('input')?.focus();
  };
  // New finding from the ticked rows of the list of marked events in no finding opens the form in place, with the words
  // typed in the new finding's form already open
  const fromTicked = (uids) => {
    const node = form.querySelector('.finding-form');
    const open = node ? drafts.get(node)?.() : null;
    const typed = open && hasWords(open) ? open : null;
    openForm(uids, typed);
    if (typed) reportAction(`The new finding's form keeps what was typed in it, now for ${plural(uids.length, 'ticked event')}.`);
  };
  const selected = [...S.selected];
  const newButton = button(selected.length ? `New finding from ${targetWords(selected)}` : 'New finding', () => openForm([...S.selected]),
                           { title: 'A finding is your conclusion, in your words, with the events that support it. The app writes none of it.' });
  const counts = open.length || retired.length
    ? `${plural(open.length, 'finding')}${retired.length ? `, ${retired.length} retired` : ''}` : 'No findings yet';
  left.append(
    // The band says Findings; the heading says more, as To investigate's do: whose words these are
    el('div', { class: 'inv-head' }, el('h2', {}, 'Findings you wrote'), el('span', { class: 'muted' }, counts), newButton),
    form, slot,
    ...open.map((f) => findingCard(f, slot, kept.edits.get(f.id), kept.retiring.get(f.id))),
    ...(open.length ? [] : [el('p', { class: 'muted' },
      'A finding is a short conclusion you write, with its supporting events linked. Select events on the timeline or in a list, ' +
      'then New finding here, or Add to a finding on an event\'s page.')]),
    unassigned(res.unassigned, fromTicked),
    ...(retired.length ? [fold(`Retired findings (${retired.length})`, 'glessner.retiredFindingsOpen',
                               retired.map((f) => findingCard(f, slot)), { cls: 'retired-fold' })] : []));
  // The report, the exports, and the files written (exports.js). The Summary with the focus shows its text at once.
  const summary = kept.summary ?? (focus?.label === 'Summary' && !focus.scope ? focus.text : null);
  const right = exportsColumn({ summary });
  setPage(PAGE, [...readOnlyHint(), el('div', { class: 'findings-page' }, left, right)],
          { title: 'Findings', reopen: () => showFindings() });
  const notes = [];   // what the status line says of the draft the page opened
  if (newFrom) {
    const typed = kept.added && hasWords(kept.added) ? kept.added : null;
    openForm(newFrom, typed);
    if (typed) {
      notes.push("The new finding's form kept from before the reload is back with what was typed in it, " +
                 `now for ${targetWords(newFrom)}.`);
    }
  } else if (kept.added) {
    form.replaceChildren(findingForm({ targets: kept.added.targets, slot, onCancel: closeForm, draft: kept.added }));
  }
  refocus(focus);
  drew(PAGE, () => showFindings({ keep: true }));
  const lost = [...kept.edits.keys()].filter((id) => !open.some((f) => f.id === id)).length;
  if (lost) notes.push(retiredWords(lost));
  if (notes.length) reportAction(notes.join(' '));
  return lost;
}

// Where the focus is, in a field of the Findings page: its finding's card or the new finding's form (`scope`, a
// selector, or null for the rest of the page), its name, its text, and the caret. Null when no such field has it.
function focusedField() {
  const node = document.activeElement;
  const label = node?.getAttribute('aria-label');
  if (!label || !node.matches('input[type="text"], textarea, select') || !$('detailsBody').contains(node)) return null;
  const card = node.closest('[data-finding]');
  const scope = card ? `.finding[data-finding="${card.dataset.finding}"]` : node.closest('.finding-new') ? '.finding-new' : null;
  return { scope, label, text: node.value, start: node.selectionStart ?? null, end: node.selectionEnd ?? null };
}

// Put the focus back in the field focusedField gave, as the page drew it again, with its caret
function refocus(field) {
  if (!field) return;
  const body = $('detailsBody');
  const within = field.scope ? body.querySelector(field.scope) : body;
  const node = [...(within?.querySelectorAll(`[aria-label="${CSS.escape(field.label)}"]`) ?? [])]
    .find((n) => field.scope || !n.closest('[data-finding], .finding-new'));
  if (!node) return;
  node.focus();
  if (field.start !== null && node.setSelectionRange) node.setSelectionRange(field.start, field.end);
}

// What the status line says of edit forms that couldn't open again, as their findings were retired since
const retiredWords = (n) => (n === 1 ? 'The finding being edited was retired, so its changes are not kept.'
  : `${n} findings being edited were retired, so their changes are not kept.`);

// Whether a new finding's form, as a draft gives it, holds anything typed or picked
const hasWords = (d) => Boolean(d.title || d.severity || d.narrative || d.techniques.length);

// What the Findings page on screen holds that isn't saved, for the place a reload puts back: each open finding form, new
// or an edit, with its fields, and the Summary's unsaved text (exports.js). A draft a reload kept that no Findings page
// has drawn is given back whole, whatever is on screen. Null when there is none, and while another step is on screen,
// such as the overview over this page: the Findings step draws the page anew, without the forms it had.
export function findingsDraft() {
  if (unshown) return unshown;
  if (S.tab !== PAGE || $('details').dataset.page !== PAGE) return null;
  return pageDraft();
}

// The open finding forms in the Details panel, with their fields, the retire reasons open (`retiring`, each with its
// finding), and the Summary's unsaved text, or null when there is none of them. A form whose change was saved has left
// `drafts`, so it isn't among them. `settled` also leaves out each form whose write is still out, as a redraw after a
// change does: the write closes its form when it answers, and a form drawn again meanwhile would stay open after its
// change was saved.
function pageDraft({ settled = false } = {}) {
  const body = $('detailsBody');
  const forms = [...body.querySelectorAll('.finding-form')].filter((node) => !(settled && saving.has(node)))
    .map((node) => drafts.get(node)?.()).filter(Boolean);
  const retiring = [...body.querySelectorAll('.finding-retire')].map((row) => ({
    finding: Number(row.closest('[data-finding]').dataset.finding), reason: row.querySelector('input').value }));
  const summary = summaryDraft();
  return forms.length || retiring.length || summary !== null ? { forms, retiring, summary } : null;
}

// Two drafts as one, the later's forms and Summary text over the earlier's, or whichever there is
function joinDrafts(earlier, later) {
  if (!earlier || !later) return earlier || later;
  const list = (v) => (Array.isArray(v) ? v : []);
  return { forms: [...list(earlier.forms), ...list(later.forms)], retiring: [...list(earlier.retiring), ...list(later.retiring)],
           summary: later.summary ?? earlier.summary };
}

// A draft as the tab's storage gives it back, kept to the shape findingsDraft writes: the new finding's form (`added`),
// the edit forms, each with the value each field counts as edited from (`opened`, or null), and the retire reasons by
// finding, and the Summary's text, or null
function keptDraft(draft) {
  const text = (v) => (typeof v === 'string' ? v : '');
  const strings = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);
  const fieldsOf = (v) => ({ title: text(v.title), severity: text(v.severity), narrative: text(v.narrative), techniques: strings(v.techniques) });
  const kept = { added: null, edits: new Map(), retiring: new Map(),
                 summary: typeof draft?.summary === 'string' ? draft.summary : null };
  for (const d of Array.isArray(draft?.forms) ? draft.forms : []) {
    if (!d || typeof d !== 'object') continue;
    if (Number.isInteger(d.finding)) {
      kept.edits.set(d.finding, { ...fieldsOf(d), opened: d.opened && typeof d.opened === 'object' ? fieldsOf(d.opened) : null });
    } else kept.added = { ...fieldsOf(d), targets: strings(d.targets) };
  }
  for (const r of Array.isArray(draft?.retiring) ? draft.retiring : []) {
    if (Number.isInteger(r?.finding)) kept.retiring.set(r.finding, text(r.reason));
  }
  return kept;
}

// The events a button acts on, named as Save trail names its event: "the 4624 on DC01" for the one event in focus, else
// "the N selected events".
export function targetWords(uids) {
  const n = uids.length;
  if (n === 1 && S.focusEvent && S.focusEvent.uid === uids[0]) return `the ${S.focusEvent.short} on ${S.focusEvent.host}`;
  return n === 1 ? 'the selected event' : `the ${n.toLocaleString()} selected events`;
}

// The worded severity chip, on the Hayabusa level chips' pattern: a border in the level's color, the word inside
export const severityChip = (sev) => el('span', { class: `chip level-${String(sev).toLowerCase()}` }, sev);

// One finding's card: the chip, its number and title, the narrative, the ATT&CK line, the event chips, and the caveats.
// Edit opens the fields in place, with an Unlink on each event chip; Retire asks for its reason; a retired card shows the
// reason and Restore. Given an edit form's `draft`, kept across a reload, the card opens in edit mode with its fields,
// and given a retire `reason`, kept from the page drawn before, with Retire's reason open with its words.
function findingCard(f, slot, draft = null, reason = null) {
  const card = el('article', { class: `finding${f.retired ? ' retired' : ''}`, 'data-finding': String(f.id) });
  let retiring = reason;   // for the first draw only: Cancel in an edit form draws the card again with Retire closed
  const draw = (editing = false, fields = null) => {
    const title = el('b', { class: 'finding-title' }, `${f.number}. ${f.title}`);
    const acts = el('span', { class: 'acts' });
    const head = el('div', { class: 'finding-head' }, severityChip(f.severity), title, acts);
    const parts = [head];
    if (f.retired) {
      acts.append(button('Restore', () => change({ op: 'restore', finding: f.id }, `Restored the finding "${f.title}"`)));
      parts.push(el('div', { class: 'finding-line' }, `Retired ${fmtAt(f.retired.at)} by ${f.retired.who}` +
                 (f.retired.reason ? `. Reason: ${f.retired.reason}` : '')));
    } else if (editing) {
      head.replaceChildren(severityChip(f.severity), el('b', { class: 'finding-title' }, `${f.number}.`));
      parts.push(findingForm({ finding: f, slot, onCancel: () => draw(false), draft: fields }));
    } else {
      acts.append(button('Edit', () => draw(true), { class: 'quiet' }), retireButton(f, retiring));
      retiring = null;
    }
    if (!editing && f.narrative) parts.push(el('p', { class: 'finding-narr' }, f.narrative));
    if (!editing) {
      const when = f.edited ? `edited ${fmtAt(f.edited.at)} by ${f.edited.who}` : `added ${fmtAt(f.added.at)} by ${f.added.who}`;
      parts.push(el('div', { class: 'finding-line' },
        `ATT&CK: ${f.techniques.length ? techniqueWords(f) : 'none given'} · ${plural(f.total, 'supporting event')} · ${when}`));
    }
    parts.push(eventChips(f, editing && !f.retired));
    if (f.caveats.length) parts.push(caveatList(f.caveats));
    card.replaceChildren(...parts);
  };
  draw(!!draft, draft);
  return card;
}

// A finding's techniques as the card and the report write them: an ID that isn't listed has the server's flag in brackets
const techniqueWords = (f) => f.techniques.map((t) => (f.technique_flags?.[t] ? `${t} (${f.technique_flags[t]})` : t)).join(', ');

// The linked events as chips: the badge (its current mark), the code or kind, the host, and the time; the first CHIPS, then
// "+N more". A click opens the event. In edit mode each chip has Unlink.
function eventChips(f, editing) {
  const box = el('div', { class: 'finding-events' });
  const chip = (e) => {
    const when = e.ts == null ? 'no time' : fmtUs(e.ts).slice(11, 19);
    const what = e.code || artifactName(e.artifact);   // the event code, or the kind of record
    // The pill holds the badge and the link; the link itself stays the one global link-like button, restyled by nothing
    const open = el('button', { type: 'button', class: 'linklike', title: `${fmtUs(e.ts)}  ${e.host}  ${codePrefix(e)}${e.msg}`,
                                onclick: () => { S.selected = new Set([e.uid]); S.focus = e.uid; S.windowLinks = []; loadDetails(e.uid, e.ts); } },
                    `${what} ${e.host} ${when}`);
    const pill = el('span', { class: 'ev-chip', 'data-uid': e.uid }, markBadge(e), open);
    if (!editing) return pill;
    return el('span', { class: 'ev-chip-edit' }, pill,
      button('Unlink', () => change({ op: 'unlink', finding: f.id, targets: [e.uid] }, `Unlinked 1 event from the finding "${f.title}"`),
             { class: 'quiet small', title: `Unlink ${what} ${e.host} ${when} from this finding` }));
  };
  const first = f.events.slice(0, CHIPS), rest = f.events.slice(CHIPS);
  box.append(...first.map(chip));
  if (rest.length) {
    const more = el('div', { class: 'finding-events', hidden: '' }, ...rest.map(chip));
    const toggle = button(`+${rest.length.toLocaleString()} more`, () => {
      more.hidden = !more.hidden;
      toggle.setAttribute('aria-expanded', String(!more.hidden));
      toggle.textContent = more.hidden ? `+${rest.length.toLocaleString()} more` : 'Fewer';
      (more.hidden ? box : more).append(toggle);   // the toggle follows the last chip shown
    }, { class: 'linklike more', 'aria-expanded': 'false' });
    box.append(toggle);
    const wrap = el('div', {}, box, more);
    if (f.total > f.events.length) wrap.append(el('div', { class: 'muted finding-line' }, `Listing the first ${f.events.length} of ${f.total.toLocaleString()}.`));
    return wrap;
  }
  if (!f.events.length) box.append(el('span', { class: 'muted' }, 'No events linked yet.'));
  return box;
}

// The fields of a finding, for a new one (`targets`) or an edit (`finding`). Save sends the add, or an edit of the fields the
// analyst changed; a new finding of more than CONFIRM_ABOVE events asks first, and the server then records the
// consent. The fields open as `draft` gives them, when a reload kept one, and findingsDraft reads them back.
// An edit form's draft holds the finding's fields as they were when the form opened (`opened`), which tells the fields the
// analyst edited from the ones the finding changed since. A field the finding has changed since, which the draft left as
// it was opened, takes the finding's value, so a change made in another tab isn't sent back as this analyst's edit. A
// field the analyst edited keeps their words, and a line names every field the finding changed. Save sends the fields
// that differ from the finding as the page read it, so a field the analyst set back to its value from when the form
// opened is written over a change made since. The draft records such a field with the finding's current value as its
// `opened`, so the field differs from it and the next reload counts it as edited too.
// Save and Cancel are disabled while the write is out, so a second click can't send it again.
function findingForm({ finding = null, targets = [], slot, onCancel, draft = null }) {
  const f = finding || { title: '', severity: '', narrative: '', techniques: [], technique_flags: {} };
  const opened = finding ? (draft?.opened ?? pickFields(f)) : null;
  const moved = finding ? FIELDS.filter((k) => !same(opened[k], f[k])) : [];
  const taken = new Set(moved.filter((k) => same(draft[k], opened[k])));
  const origin = (k) => (taken.has(k) ? f[k] : opened[k]);   // the value this form counts a field as edited from
  const openedAs = (now) => Object.fromEntries(FIELDS.map((k) => [k, same(now[k], origin(k)) ? f[k] : origin(k)]));
  const start = (k) => (draft && !taken.has(k) ? draft[k] : f[k]);
  const title = el('input', { type: 'text', 'aria-label': 'Title', placeholder: 'Title: your conclusion in one line', maxlength: '200' });
  title.value = start('title');
  const severity = el('select', { 'aria-label': 'Severity' },
    el('option', { value: '', disabled: '' }, 'Severity'), ...SEVERITIES.map((s) => el('option', { value: s }, s)));
  severity.value = start('severity');
  const narrative = el('textarea', { 'aria-label': 'Narrative', placeholder: 'Narrative: what happened, in your words (optional)' });
  narrative.value = start('narrative');
  const techniques = attackField(start('techniques'), f.technique_flags);   // a pick list of Enterprise ATT&CK's techniques
  const problem = el('p', { class: 'warn', hidden: '' });
  const changedNote = moved.length
    ? [el('p', { class: 'warn finding-changed', role: 'status' }, `Changed since this form opened: ${moved.join(', ')}. ` +
         'It shows the finding\'s current values, except in a field you edited, which keeps your words.')] : [];
  const n = targets.length;
  const write = async (body, said) => {
    busy(true);
    if (!await change(body, said, PAGE, node)) {   // refused: the form stays, for another try
      busy(false);
      save.focus();
    }
  };
  const save = button(finding ? 'Save changes' : n ? `Add the finding with ${plural(n, 'event')}` : 'Add the finding', async () => {
    const ids = techniques.ids();
    const refused = !title.value.trim() || !severity.value ? 'A finding needs a title and a severity.' : techniques.problem(f.techniques);
    if (refused) {
      problem.textContent = refused;
      problem.hidden = false;
      return;
    }
    problem.hidden = true;
    const fields = { title: title.value, severity: severity.value, narrative: narrative.value, techniques: ids };
    if (finding) {
      const changed = Object.fromEntries(Object.entries(fields).filter(([k, v]) => !same(v, f[k])));
      if (!Object.keys(changed).length) { onCancel(); return; }
      await write({ op: 'edit', finding: f.id, ...changed }, `Edited the finding "${fields.title}": ${Object.keys(changed).join(', ')}`);
      return;
    }
    const consent = {};
    if (n > CONFIRM_ABOVE) {
      if (!await askSelection({ action: `Link ${plural(n, 'event')} to a new finding`, uids: targets, host: slot,
                                effect: `All ${n.toLocaleString()} are linked to the new finding. Their marks and tags don't change.` })) return;
      consent.confirmed = { count: n };
    }
    await write({ op: 'add', ...fields, targets, ...consent }, `Added the finding "${fields.title}"${n ? ` with ${plural(n, 'event')}` : ''}`);
  });
  const cancel = button('Cancel', onCancel);
  const busy = (on) => { save.disabled = on; cancel.disabled = on; };
  const node = el('div', { class: 'finding-form' }, ...changedNote, title, el('div', { class: 'actions attack-row' }, severity, techniques.node),
    narrative, problem, el('div', { class: 'actions' }, save, cancel));
  drafts.set(node, () => {
    const now = { title: title.value, severity: severity.value, narrative: narrative.value, techniques: techniques.ids() };
    return { ...(finding ? { finding: f.id, opened: openedAs(now) } : { targets }), ...now };
  });
  return node;
}

// Retire asks for its reason in place; the reason goes on the entry and shows on the retired card. `kept`, a reason kept
// from the page drawn before, opens the row with its words in place of the button.
function retireButton(f, kept = null) {
  const open = (text) => {
    const reason = el('input', { type: 'text', 'aria-label': 'Reason', placeholder: 'Reason (optional)', size: '32' });
    reason.value = text;
    const row = el('div', { class: 'actions finding-retire' }, reason,
      button('Retire the finding', () => change({ op: 'retire', finding: f.id, reason: reason.value }, `Retired the finding "${f.title}"`)),
      button('Cancel', () => { row.replaceWith(retire); retire.focus(); }));
    return { row, reason };
  };
  const retire = button('Retire', () => {
    const { row, reason } = open('');
    retire.replaceWith(row);
    reason.focus();
  }, { class: 'quiet' });
  return kept === null ? retire : open(kept).row;
}

// One write through /api/finding, reported on the status line with the server's time; a refusal is the status line's
// action. The page it was made on, Findings or an Event page (`page`, its key), then redraws, not over a page asked for
// meanwhile. `form` is the finding form whose fields the write saves: the Findings page drawn again keeps its other forms
// open, and not that one. When the write fails after a redraw left the form out, the form opens again, unless another
// form of its kind has taken its place (reopen).
async function change(body, said, page = PAGE, form = null) {
  const done = pageAction(page);
  if (form) saving.add(form);
  try {
    const res = await post('/api/finding', body);
    titles = null;
    if (form) drafts.delete(form);
    reportAction(said, res.server_ms);
    done();
    return res;
  } catch (err) {
    const back = form && !form.isConnected ? ` ${reopen(form, done)}` : '';
    setStatus(`Finding change failed: ${err.message}${back}`);
    return null;
  } finally {
    if (form) saving.delete(form);
  }
}

// A form a redraw left out while its write was out, whose write then failed: its words go to the page's next draw, at
// once when the page can draw now (`done`, pageAction's). The page opens one new finding's form, and one edit form for
// each finding, so a form of the same kind open on the Findings page, or waiting for the page's next draw, keeps its
// place, and the words that failed aren't kept. Returns what the status line says of it.
function reopen(form, done) {
  const draft = drafts.get(form)?.();
  if (!draft) return '';
  const edit = Number.isInteger(draft.finding);
  const open = keptDraft(joinDrafts(unshown, $('details').dataset.page === PAGE ? pageDraft() : null));
  if (edit ? open.edits.has(draft.finding) : open.added) {
    return `What was typed in its form isn't kept: another ${edit ? 'edit form of the finding' : "new finding's form"} takes its place.`;
  }
  unshown = joinDrafts(unshown, { forms: [draft], retiring: [], summary: null });
  return done() ? 'Its form is open again with what was typed in it.' : 'Its form opens again with the Findings page.';
}

// "N marked events are in no finding yet", with Show them, which lists them in the list row grid with their ticks
function unassigned(n, fromTicked) {
  if (!n) return el('div', { class: 'unassigned' }, el('b', {}, 'Every marked event is in a finding.'));
  const box = el('div', { class: 'unassigned' },
    el('b', {}, `${plural(n, 'marked event')} ${n === 1 ? 'is' : 'are'} in no finding yet.`),
    el('span', { class: 'muted' }, `${n === 1 ? 'It' : 'They'} still appear${n === 1 ? 's' : ''} in the report's timeline.`));
  const list = el('div', { class: 'related unassigned-list', hidden: '' });
  const { checked } = unfiled;
  let events = null;
  const render = () => {
    // The find box; a list cut at the server's LISTED_EVENTS says how far it reaches
    const find = { page: PAGE, name: 'unassigned', covers: 'The count still covers',
                   listed: events.length < n ? events.length : null, total: n, more: 'events' };
    // After a mark, the page redraws, with the list read again, not over a page asked for meanwhile
    const made = markableList(events, checked, render, (done) => done(), { find, afterTag: showList });
    const toFinding = checked.size ? [button(`New finding from the ${checked.size} ticked`, () => fromTicked([...checked]))] : [];
    // The server lists at most its LISTED_EVENTS, so above that the heading says it is the first of them
    const heading = events.length < n ? `The first ${events.length.toLocaleString()} of ${plural(n, 'marked event')} in no finding`
      : `${plural(events.length, 'marked event')} in no finding`;
    const cut = events.length < n;
    list.replaceChildren(el('div', { class: 'actions' }, el('strong', {}, heading),
                            ...made.buttons, ...toFinding, made.find.box),
                         ...(cut ? [made.find.foot, made.list] : [made.list, made.find.foot]));
  };
  // Reads the list and draws it; returns whether the read answered. The ticks the list keeps are of events it still
  // lists: an event filed in a finding since leaves it.
  const showList = async () => {
    try { events = (await api('/api/findings_page?unassigned=1')).unassigned_events; }
    catch (err) { setStatus(`Could not list them: ${err.message}`); return false; }
    const listed = new Set(events.map((e) => e.uid));
    for (const uid of [...checked]) if (!listed.has(uid)) checked.delete(uid);
    render();
    return true;
  };
  const toggle = (open) => {
    list.hidden = !open;
    unfiled.open = open;
    show.textContent = open ? 'Hide them' : 'Show them';
    show.setAttribute('aria-expanded', String(open));
  };
  const show = button('Show them', async () => {
    if (!list.hidden) toggle(false);
    else if (events || await showList()) toggle(true);
  }, { class: 'linklike', 'aria-expanded': 'false' });
  box.append(show);
  if (unfiled.open) showList().then((read) => { if (read) toggle(true); });
  return el('div', {}, box, list);
}

// ---------- Caveats ----------

// The sources of a caveat: a public source is a link, a file of the project is named with its path in the hover
function sourceNodes(sources) {
  return sources.flatMap((s, i) => [...(i ? [' · '] : []),
    s.url ? el('a', { href: s.url, target: '_blank', rel: 'noopener' }, s.title) : el('span', { title: s.path }, s.title)]);
}

// The Event page's caveat beside the record: "What this does not prove", the text, its
// sources, and Show less, which folds it to its title and is remembered in this browser
export function caveatBox(caveat) {
  if (!caveat) return null;
  let open = true;
  try { open = localStorage.getItem(CAVEAT_OPEN_KEY) !== '0'; } catch (_) { /* storage blocked */ }
  const box = el('div', { class: `caveat ev-caveat${open ? '' : ' collapsed'}`, 'data-caveat': caveat.id });
  const toggle = button(open ? 'Show less' : 'Show more', () => {
    open = !open;
    box.classList.toggle('collapsed', !open);
    toggle.textContent = open ? 'Show less' : 'Show more';
    toggle.setAttribute('aria-expanded', String(open));
    try { localStorage.setItem(CAVEAT_OPEN_KEY, open ? '1' : '0'); } catch (_) { /* storage blocked */ }
  }, { class: 'linklike caveat-more', 'aria-expanded': String(open) });
  // The label and separators sit in a span, so the fold hides them with the sources and leaves only Show more
  box.append(el('b', { class: 'caveat-title' }, 'What this does not prove'), el('span', { class: 'caveat-text' }, caveat.text),
             el('div', { class: 'caveat-src' },
                el('span', {}, `Source${caveat.sources.length === 1 ? '' : 's'}: `, ...sourceNodes(caveat.sources), ' · '), toggle));
  return box;
}

// A finding's caveats: those of its events' types, each named, with its sources
function caveatList(caveats) {
  return el('div', { class: 'caveat finding-caveat' }, el('b', { class: 'caveat-title' }, 'What this does not prove'),
    ...caveats.map((c) => el('p', { 'data-caveat': c.id }, el('b', {}, `${c.name}. `), c.text, ' ',
                             el('span', { class: 'caveat-src' }, `Source${c.sources.length === 1 ? '' : 's'}: `, ...sourceNodes(c.sources)))));
}

// ---------- Add to a finding, from the Event page ----------

// For the header's verdict zone: `plus` is a "+ Finding" button for its second row, beside + Tag, whose hover names the
// target; `rows` go to the header's third row: "In the finding: 1. ..." (each a link to the page) when the event is in
// one, and the picker the button opens, hidden until then, so a page with nothing to say keeps its two rows. The picker
// adds the event, or the selection, to a finding, with a bordered button naming its target as Save trail does. A link
// of more than CONFIRM_ABOVE events asks first. "New finding" opens the page's form over the same events.
export function findingRow(ev, uids) {
  const n = uids.length;
  const inFindings = (ev.findings || []).flatMap((f, i) => [...(i ? [', '] : []),
    button(`${f.number}. ${f.title}`, () => showFindings(), { class: 'linklike', title: 'Open the Findings page' })]);
  const pick = el('select', { 'aria-label': 'Finding to add to' }, el('option', { value: '' }, 'Choose a finding'));
  const fill = (list) => {
    pick.replaceChildren(el('option', { value: '' }, list.length ? 'Choose a finding' : 'No open finding yet'),
                         ...list.map((f) => el('option', { value: String(f.id) }, `${f.number}. ${f.title}`)),
                         el('option', { value: 'new' }, 'New finding…'));
  };
  const add = button(`Add ${targetWords(uids)}`, async () => {
    if (!pick.value) { setStatus('Choose the finding to add to, or New finding.'); return; }
    if (pick.value === 'new') { showFindings({ newFrom: uids }); return; }
    const f = (titles || []).find((x) => String(x.id) === pick.value);
    const consent = {};
    if (n > CONFIRM_ABOVE) {   // the block goes to the page's confirm slot (under the selection list), or the top of the body
      if (!await askSelection({ action: `Link ${plural(n, 'event')} to the finding "${f?.title || ''}"`, uids,
                                effect: `All ${n.toLocaleString()} are linked to the finding. Their marks and tags don't change.` })) return;
      consent.confirmed = { count: n };
    }
    await change({ op: 'link', finding: Number(pick.value), targets: uids, ...consent },
                 `Linked ${plural(n, 'event')} to the finding "${f?.title || ''}"`, `event:${S.focus}`);
  }, { title: 'Link the event to the finding it supports. The finding stays yours to word.' });
  const picker = el('div', { class: 'verdict-row small finding-add', hidden: '' }, el('span', { class: 'muted' }, 'Finding:'), pick, add);
  const plus = button('+ Finding', () => {
    picker.hidden = !picker.hidden;
    plus.setAttribute('aria-expanded', String(!picker.hidden));
    if (picker.hidden) return;
    if (titles) fill(titles);   // the open findings are read when the picker opens, not with every Event page
    else {
      api('/api/findings_page').then((res) => {
        titles = res.findings.filter((f) => !f.retired).map((f) => ({ id: f.id, number: f.number, title: f.title }));
        fill(titles);
      }).catch(() => fill([]));
    }
    pick.focus();
  }, { class: 'quiet', 'aria-expanded': 'false', title: `Add ${targetWords(uids)} to a finding` });
  const rows = inFindings.length
    ? [el('div', { class: 'verdict-row small finding-in' }, el('span', { class: 'muted' }, 'In the finding: '), ...inFindings)] : [];
  return { plus, rows: [...rows, picker] };
}
