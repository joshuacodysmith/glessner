import { attackField, attackList } from './attack.js';
import { askSelection, CONFIRM_ABOVE } from './confirm.js';
import { api, codePrefix, el, fmtAt, fmtUs, markBadge, plural, post, reportAction, S, setStatus } from './core.js';
import { artifactName, button, claimDetails, fold, loadDetails, readOnlyHint, setPage, showingPage } from './event_page.js';
import { exportsColumn } from './exports.js';
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

let titles = null;   // the open findings' numbers and titles, for the Event page's picker; cleared by every write

// Draw the page. `newFrom` opens the new-finding form over these events, as "New finding" from the Event page does.
export async function showFindings({ newFrom = null } = {}) {
  const latest = claimDetails();
  let res;
  try { res = await api('/api/findings_page'); }
  catch (err) {
    if (latest()) setPage(PAGE, [el('p', { class: 'pad' }, `Could not load the findings: ${err.message}`)]);
    return;
  }
  if (!latest()) return;
  attackList().catch(() => {});   // the ATT&CK field's list, read before a form opens; a form says so if it fails
  titles = res.findings.filter((f) => !f.retired).map((f) => ({ id: f.id, number: f.number, title: f.title }));
  const refresh = () => { if (showingPage(PAGE)) showFindings(); };
  const open = res.findings.filter((f) => !f.retired), retired = res.findings.filter((f) => f.retired);
  const left = el('section', { class: 'findings-col' });
  const slot = el('div', { class: 'confirm-slot' });
  const form = el('div', { class: 'finding-new' });
  const selected = [...S.selected];
  const newButton = button(selected.length ? `New finding from ${targetWords(selected)}` : 'New finding', () => {
    form.replaceChildren(findingForm({ targets: [...S.selected], slot, onDone: refresh, onCancel: () => form.replaceChildren() }));
    form.querySelector('input')?.focus();
  }, { title: 'A finding is your conclusion, in your words, with the events that support it. The app writes none of it.' });
  const counts = open.length || retired.length
    ? `${plural(open.length, 'finding')}${retired.length ? `, ${retired.length} retired` : ''}` : 'No findings yet';
  left.append(
    // The band says Findings; the heading says more, as To investigate's do: whose words these are
    el('div', { class: 'inv-head' }, el('h2', {}, 'Findings you wrote'), el('span', { class: 'muted' }, counts), newButton),
    form, slot,
    ...open.map((f) => findingCard(f, refresh, slot)),
    ...(open.length ? [] : [el('p', { class: 'muted' },
      'A finding is a short conclusion you write, with its supporting events linked. Select events on the timeline or in a list, ' +
      'then New finding here, or Add to a finding on an event\'s page.')]),
    unassigned(res.unassigned, refresh),
    ...(retired.length ? [fold(`Retired findings (${retired.length})`, 'glessner.retiredFindingsOpen',
                               retired.map((f) => findingCard(f, refresh, slot)), { cls: 'retired-fold' })] : []));
  const right = exportsColumn();   // the report, the exports, and the files written (exports.js)
  setPage(PAGE, [...readOnlyHint(), el('div', { class: 'findings-page' }, left, right)],
          { title: 'Findings', reopen: () => showFindings() });
  if (newFrom) {
    form.replaceChildren(findingForm({ targets: newFrom, slot, onDone: refresh, onCancel: () => form.replaceChildren() }));
    form.querySelector('input')?.focus();
  }
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
// reason and Restore.
function findingCard(f, refresh, slot) {
  const card = el('article', { class: `finding${f.retired ? ' retired' : ''}`, 'data-finding': String(f.id) });
  const draw = (editing = false) => {
    const title = el('b', { class: 'finding-title' }, `${f.number}. ${f.title}`);
    const acts = el('span', { class: 'acts' });
    const head = el('div', { class: 'finding-head' }, severityChip(f.severity), title, acts);
    const parts = [head];
    if (f.retired) {
      acts.append(button('Restore', () => change({ op: 'restore', finding: f.id }, `Restored the finding "${f.title}"`, refresh)));
      parts.push(el('div', { class: 'finding-line' }, `Retired ${fmtAt(f.retired.at)} by ${f.retired.who}` +
                 (f.retired.reason ? `. Reason: ${f.retired.reason}` : '')));
    } else if (editing) {
      head.replaceChildren(severityChip(f.severity), el('b', { class: 'finding-title' }, `${f.number}.`));
      parts.push(findingForm({ finding: f, slot, onDone: refresh, onCancel: () => draw(false) }));
    } else {
      acts.append(button('Edit', () => draw(true), { class: 'quiet' }), retireButton(f, refresh));
    }
    if (!editing && f.narrative) parts.push(el('p', { class: 'finding-narr' }, f.narrative));
    if (!editing) {
      const when = f.edited ? `edited ${fmtAt(f.edited.at)} by ${f.edited.who}` : `added ${fmtAt(f.added.at)} by ${f.added.who}`;
      parts.push(el('div', { class: 'finding-line' },
        `ATT&CK: ${f.techniques.length ? techniqueWords(f) : 'none given'} · ${plural(f.total, 'supporting event')} · ${when}`));
    }
    parts.push(eventChips(f, editing && !f.retired, refresh));
    if (f.caveats.length) parts.push(caveatList(f.caveats));
    card.replaceChildren(...parts);
  };
  draw();
  return card;
}

// A finding's techniques as the card and the report write them: an ID that isn't listed has the server's flag in brackets
const techniqueWords = (f) => f.techniques.map((t) => (f.technique_flags?.[t] ? `${t} (${f.technique_flags[t]})` : t)).join(', ');

// The linked events as chips: the badge (its current mark), the code or kind, the host, and the time; the first CHIPS, then
// "+N more". A click opens the event. In edit mode each chip has Unlink.
function eventChips(f, editing, refresh) {
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
      button('Unlink', () => change({ op: 'unlink', finding: f.id, targets: [e.uid] }, `Unlinked 1 event from the finding "${f.title}"`, refresh),
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

// The fields of a finding, for a new one (`targets`) or an edit (`finding`). Save sends the add, or an edit of the fields that
// changed; a new finding of more than CONFIRM_ABOVE events asks first, and the server then records the consent.
function findingForm({ finding = null, targets = [], slot, onDone, onCancel }) {
  const f = finding || { title: '', severity: '', narrative: '', techniques: [], technique_flags: {} };
  const title = el('input', { type: 'text', 'aria-label': 'Title', placeholder: 'Title: your conclusion in one line', maxlength: '200' });
  title.value = f.title;
  const severity = el('select', { 'aria-label': 'Severity' },
    el('option', { value: '', disabled: '' }, 'Severity'), ...SEVERITIES.map((s) => el('option', { value: s }, s)));
  severity.value = f.severity;
  const narrative = el('textarea', { 'aria-label': 'Narrative', placeholder: 'Narrative: what happened, in your words (optional)' });
  narrative.value = f.narrative;
  const techniques = attackField(f.techniques, f.technique_flags);   // a pick list of Enterprise ATT&CK's techniques
  const problem = el('p', { class: 'warn', hidden: '' });
  const n = targets.length;
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
      const changed = Object.fromEntries(Object.entries(fields).filter(([k, v]) => JSON.stringify(v) !== JSON.stringify(f[k])));
      if (!Object.keys(changed).length) { onCancel(); return; }
      await change({ op: 'edit', finding: f.id, ...changed }, `Edited the finding "${fields.title}": ${Object.keys(changed).join(', ')}`, onDone);
      return;
    }
    const consent = {};
    if (n > CONFIRM_ABOVE) {
      if (!await askSelection({ action: `Link ${plural(n, 'event')} to a new finding`, uids: targets, host: slot,
                                effect: `All ${n.toLocaleString()} are linked to the new finding. Their marks and tags don't change.` })) return;
      consent.confirmed = { count: n };
    }
    await change({ op: 'add', ...fields, targets, ...consent }, `Added the finding "${fields.title}"${n ? ` with ${plural(n, 'event')}` : ''}`, onDone);
  });
  return el('div', { class: 'finding-form' }, title, el('div', { class: 'actions attack-row' }, severity, techniques.node), narrative, problem,
    el('div', { class: 'actions' }, save, button('Cancel', onCancel)));
}

// Retire asks for its reason in place; the reason goes on the entry and shows on the retired card
function retireButton(f, refresh) {
  const retire = button('Retire', () => {
    const reason = el('input', { type: 'text', 'aria-label': 'Reason', placeholder: 'Reason (optional)', size: '32' });
    const row = el('div', { class: 'actions finding-retire' }, reason,
      button('Retire the finding', () => change({ op: 'retire', finding: f.id, reason: reason.value }, `Retired the finding "${f.title}"`, refresh)),
      button('Cancel', () => { row.replaceWith(retire); retire.focus(); }));
    retire.replaceWith(row);
    reason.focus();
  }, { class: 'quiet' });
  return retire;
}

// One write through /api/finding, reported on the status line with the server's time; a refusal is the status line's
async function change(body, said, after) {
  try {
    const res = await post('/api/finding', body);
    titles = null;
    reportAction(said, res.server_ms);
    await after(res);
    return res;
  } catch (err) { setStatus(`Finding change failed: ${err.message}`); return null; }
}

// "N marked events are in no finding yet", with Show them, which lists them in the list row grid with their ticks
function unassigned(n, refresh) {
  if (!n) return el('div', { class: 'unassigned' }, el('b', {}, 'Every marked event is in a finding.'));
  const box = el('div', { class: 'unassigned' },
    el('b', {}, `${plural(n, 'marked event')} ${n === 1 ? 'is' : 'are'} in no finding yet.`),
    el('span', { class: 'muted' }, `${n === 1 ? 'It' : 'They'} still appear${n === 1 ? 's' : ''} in the report's timeline.`));
  const list = el('div', { class: 'related unassigned-list', hidden: '' });
  const checked = new Set();
  let events = null;
  const render = () => {
    // The find box; a list cut at the server's LISTED_EVENTS says how far it reaches
    const find = { page: PAGE, name: 'unassigned', covers: 'The count still covers',
                   listed: events.length < n ? events.length : null, total: n, more: 'events' };
    const made = markableList(events, checked, render, async () => { await showList(); refresh(); }, { find });
    const toFinding = checked.size
      ? [button(`New finding from the ${checked.size} ticked`, () => showFindings({ newFrom: [...checked] }))] : [];
    // The server lists at most its LISTED_EVENTS, so above that the heading says it is the first of them
    const heading = events.length < n ? `The first ${events.length.toLocaleString()} of ${plural(n, 'marked event')} in no finding`
      : `${plural(events.length, 'marked event')} in no finding`;
    const cut = events.length < n;
    list.replaceChildren(el('div', { class: 'actions' }, el('strong', {}, heading),
                            ...made.buttons, ...toFinding, made.find.box),
                         ...(cut ? [made.find.foot, made.list] : [made.list, made.find.foot]));
  };
  const showList = async () => {
    try { events = (await api('/api/findings_page?unassigned=1')).unassigned_events; }
    catch (err) { setStatus(`Could not list them: ${err.message}`); return; }
    render();
  };
  const show = button('Show them', async () => {
    if (list.hidden) { if (!events) await showList(); list.hidden = false; show.textContent = 'Hide them'; }
    else { list.hidden = true; show.textContent = 'Show them'; }
    show.setAttribute('aria-expanded', String(!list.hidden));
  }, { class: 'linklike', 'aria-expanded': 'false' });
  box.append(show);
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
    const res = await change({ op: 'link', finding: Number(pick.value), targets: uids, ...consent },
                             `Linked ${plural(n, 'event')} to the finding "${f?.title || ''}"`, async () => {});
    if (res && S.focus) loadDetails(S.focus);
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
