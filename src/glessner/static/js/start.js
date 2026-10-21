// The start page: shown when no case is open, or from the Cases button. Recent cases to open
// or copy for a clean round, a case folder to open, and a new case: the folders are checked as they're chosen, the
// evidence is hashed with progress, and the case then opens on its Tools page. Paths come from the analyst and folder
// names from this computer, so they only ever go in as text.

import { $, api, el, plural, post, setStatus, skippedLinks } from './core.js';

// The analyst starts as the Windows account /api/start names, and every action in the case is credited to it,
// so the forms show it in a field the analyst sees and can change.
const START = { info: null, form: { name: '', analyst: null, evidence: '', case_folder: '', tools: '', host: '' }, caseFolderEdited: false,
                checks: {}, browsing: null, copying: null, forgetting: false };
const POLL_MS = 700;
const FORGET_TITLE = 'Changes only this list. No case folder is touched.';   // the hover on the Remove buttons
let checkTimer = null;
let polling = null;

const startButton = (label, onclick, attrs = {}) => el('button', { type: 'button', onclick, ...attrs }, label);
const fmtBytes = (n) => (n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.round(n / 1e3)} KB`);
const slug = (name) => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
const parentOf = (folder) => folder.replace(/[\\/][^\\/]+[\\/]?$/, '');

async function loadStart() {
  try { START.info = await api('/api/start'); }
  catch (err) { setStatus(`Start page failed: ${err.message}`); return; }
  const last = START.info.recent[0];
  if (last && !START.form.tools) START.form.tools = last.tools_folder || '';
  if (START.form.analyst == null) START.form.analyst = START.info.analyst || '';
  setStatus('');
  render();
  if (START.info.job && !START.info.job.finished) follow();
}

function render() {
  // The build at the foot, quietly, for a report of what the analyst ran
  $('start').replaceChildren(el('div', { class: 'start-grid' }, recentColumn(), newCaseColumn()),
    el('p', { class: 'muted start-build' }, `glessner ${START.info.build}`));
}

function recentColumn() {
  const info = START.info;
  const open = info.open_case;
  const busy = info.job && !info.job.finished;
  const items = info.recent.map((r) => {
    const parts = [el('div', { class: 'name' }, r.name),
      el('div', { class: 'muted mono' }, r.folder),
      el('div', { class: 'muted' }, `Opened ${String(r.opened_utc || '').slice(0, 10)}`
        + (r.events != null ? ` · ${plural(r.events, 'event')}` : '') + (r.exists ? '' : ' · folder not found'))];
    const actions = el('div', { class: 'actions' },
      startButton('Open', () => openCase(r.folder), { 'aria-label': `Open ${r.name}` }),
      startButton('Copy', () => { START.copying = START.copying === r.folder ? null : r.folder; render(); },
             { 'aria-label': `Copy ${r.name}`, title: 'A clean copy: the same evidence and tool runs, with no marks, tags, or notes' }));
    for (const b of actions.querySelectorAll('button')) b.disabled = !r.exists || busy;
    // A case whose folder is gone can come off the list; a row whose folder is there keeps Open and Copy alone
    if (!r.exists) {
      // The name starts with the label the button shows, as Open's and Copy's do, so a spoken "Remove from list" finds it
      const remove = startButton('Remove from list', () => forget({ folder: r.folder }, r.name),
                                 { 'aria-label': `Remove from list: ${r.name}`, title: FORGET_TITLE });
      remove.disabled = !!busy || START.forgetting;
      actions.append(remove);
    }
    parts.push(actions);
    if (START.copying === r.folder) parts.push(copyForm(r));
    return el('div', { class: `start-case${open && open.folder === r.folder ? ' current' : ''}` }, ...parts);
  });
  const folder = el('input', { type: 'text', 'aria-label': 'Case folder to open', placeholder: 'D:\\Cases\\CASE01', class: 'mono' });
  const openFolder = startButton('Open', () => openCase(folder.value.trim()));
  openFolder.disabled = !!busy;   // the attribute would turn it off for any value, false included
  // Two or more cases whose folder is gone: one line above the list takes them all off
  const gone = info.recent.filter((r) => !r.exists).length;
  const removeAll = startButton(`Remove the ${gone} from the list`, () => forget({ all: true }), { title: FORGET_TITLE });
  removeAll.disabled = !!busy || START.forgetting;
  return el('section', { class: 'start-recent' },
    el('h2', {}, 'Recent cases'),
    ...(open ? [el('p', {}, `Open now: ${open.name}. `, el('a', { href: '/' }, 'Back to its timeline'))] : []),
    ...(gone > 1 ? [el('div', { class: 'actions start-missing' },
      el('span', { class: 'muted' }, `Folder not found for ${gone} cases.`), removeAll)] : []),
    ...(items.length ? items : [el('p', { class: 'muted' }, 'None yet.')]),
    el('h3', {}, 'Open a case folder'),
    el('div', { class: 'actions' }, folder, browseButton(folder, 'open'),
      openFolder),
    ...(START.browsing && START.browsing.field === 'open' ? [browser()] : []),
    // An open's progress sits under the buttons that started it; a new case's and a copy's sit under New case
    ...(info.job && info.job.kind === 'open' && (!info.job.finished || info.job.error) ? [jobBox(info.job)] : []));
}

function copyForm(r) {
  const folder = el('input', { type: 'text', value: `${r.folder}-copy`, 'aria-label': 'Folder for the copy', class: 'mono wide' });
  const name = el('input', { type: 'text', value: `${r.name} (copy)`, 'aria-label': 'Name for the copy' });
  const analyst = el('input', { type: 'text', value: START.form.analyst, 'aria-label': 'Analyst for the copy' });
  analyst.addEventListener('input', () => { START.form.analyst = analyst.value; });   // one analyst for both forms
  return el('div', { class: 'start-copy' },
    el('p', { class: 'muted' }, 'The copy keeps the evidence, the intake, and the tool runs, and starts with no marks, tags, notes, or rules.'),
    el('label', {}, 'Name ', name), el('label', {}, 'Analyst ', analyst), el('label', {}, 'Folder ', folder),
    el('div', { class: 'actions' }, startButton('Make the copy',
      () => copyCase(r.folder, folder.value.trim(), name.value.trim(), analyst.value.trim()))));
}

function field(label, key, { browse = true, placeholder = '' } = {}) {
  // The case name's box fits its example name, which the default width would cut to "Acme ransomware 2026-1";
  // the folders' boxes take the row's width.
  const input = el('input', { type: 'text', value: START.form[key], 'aria-label': label, placeholder,
                              ...(key === 'name' ? { size: '30' } : { class: 'mono wide' }) });
  input.addEventListener('input', () => {
    START.form[key] = input.value;
    if (key === 'case_folder') START.caseFolderEdited = true;
    if (key === 'name' && !START.caseFolderEdited) suggestCaseFolder();
    scheduleCheck();
  });
  const check = START.checks[key];
  const note = check ? el('div', { class: check.ok ? 'ok' : 'warn' }, checkNote(key, check)) : el('div');
  note.dataset.check = key;
  const notes = [note];
  if (key === 'evidence') {
    const copies = el('div', { class: 'warn' });
    copies.dataset.check = 'evidence-copies';
    showCopies(copies, check);
    notes.push(copies);
  }
  return el('div', { class: 'start-field' }, el('span', { class: 'muted' }, label),
    el('div', {}, el('div', { class: 'actions' }, input, ...(browse ? [browseButton(input, key)] : [])),
      ...(START.browsing && START.browsing.field === key ? [browser()] : []), ...notes));
}

// Several copies of one collection in the evidence folder: a warning under the check, which leaves the
// case free to be created.
function showCopies(node, c) {
  node.textContent = (c && c.warning) || '';
  node.hidden = !node.textContent;
}

function checkNote(key, c) {
  // The tools folder: each executable detection would run, one per line, so a file in the wrong place shows.
  if (key === 'tools' && c.ok) return [c.message, ...c.executables.map((x) => `${x.tool}: ${x.path}`)].join('\n');
  if (key !== 'evidence' || !c.ok) return c.message || '';
  const hosts = c.hosts.length;
  const where = hosts ? `in ${plural(hosts, 'folder')}: ${c.hosts.slice(0, 6).join(', ')}${hosts > 6 ? ' ...' : ''}` : 'with no subfolders';
  return `Found ${c.partial ? 'at least ' : ''}${plural(c.files, 'file')}, ${fmtBytes(c.bytes)}, ${where}.`
    + (c.root_files ? ` ${c.root_files === 1 ? '1 file sits in the top level and belongs'
                                       : `${c.root_files} files sit in the top level and belong`} to no host.` : '')
    + (hosts === 0 ? ' For one host, name it below.' : '') + skippedLinks(c.links);
}

function suggestCaseFolder() {
  const last = START.info.recent[0];
  if (!last || !START.form.name.trim()) return;
  START.form.case_folder = `${parentOf(last.folder)}\\${slug(START.form.name)}`;
  const input = $('start').querySelector('input[aria-label="Case folder"]');
  if (input) input.value = START.form.case_folder;
}

function newCaseColumn() {
  const f = START.form;
  const oneHost = el('input', { type: 'text', value: f.host, 'aria-label': 'Host name, for a one-host collection', placeholder: 'WS-0412' });
  oneHost.addEventListener('input', () => { f.host = oneHost.value.trim(); });
  const analyst = el('input', { type: 'text', value: f.analyst, 'aria-label': 'Analyst' });
  analyst.addEventListener('input', () => { f.analyst = analyst.value; });
  const job = START.info.job;
  const busy = job && !job.finished;
  const create = startButton('Create case and take in evidence', createCase, { class: 'primary' });
  if (busy) create.disabled = true;
  return el('section', { class: 'start-new' },
    el('h2', {}, 'New case'),
    field('Case name', 'name', { browse: false, placeholder: 'Acme ransomware 2026-10' }),
    el('div', { class: 'start-field' }, el('span', { class: 'muted' }, 'Analyst'),
      el('div', {}, el('div', { class: 'actions' }, analyst),
        el('div', { class: 'muted' }, 'Every mark, note, and other change in the case is credited to this name.'))),
    field('Evidence folder', 'evidence', { placeholder: 'E:\\Collections\\ACME' }),
    field('Case folder', 'case_folder', { placeholder: 'D:\\Cases\\acme' }),
    field('Tools folder', 'tools', { placeholder: 'D:\\Tools' }),
    el('div', { class: 'start-field' }, el('span', { class: 'muted' }, 'One host'),
      el('div', {}, el('div', { class: 'actions' }, oneHost),
        el('div', { class: 'muted' }, 'Leave empty when the evidence folder holds a folder per host, as KAPE and most collection scripts write it.'))),
    el('div', { class: 'actions' }, create),
    ...(job && job.kind !== 'open' ? [jobBox(job)] : []),
    el('ol', { class: 'start-steps muted' },
      el('li', {}, 'Take in the evidence: every file hashed and identified, nothing written to it.'),
      el('li', {}, 'Tools page: run the tools for what was found.'),
      el('li', {}, 'Import page: firewall and other text logs, if any.'),
      el('li', {}, 'The timeline.')));
}

// An open's stage as one line after the case's name: "Upgrading the case format: reloading 67,858 Suricata events" reads
// "upgrading the case format, reloading 67,858 Suricata events", and the plain "Opening" adds nothing.
const openStage = (stage) => (!stage || stage === 'Opening' ? '' : `${stage[0].toLowerCase()}${stage.slice(1)}`.replace(': ', ', '));

function jobBox(job) {
  const what = job.kind === 'new' ? `New case ${job.name}` : job.kind === 'open' ? `Opening ${job.name}` : `Copy ${job.name}`;
  const count = job.total ? `, ${job.done.toLocaleString()} of ${job.total.toLocaleString()}` : '';
  let line;
  if (job.error) line = `${what} failed: ${job.error}`;
  else if (job.finished) line = job.kind === 'new' ? `${what} is ready. Opening its Tools page.`
    : job.kind === 'open' ? `${what}: done. Going to its timeline.` : `${what} is ready in ${job.case_folder}.`;
  else if (job.kind === 'open') line = `${what}${openStage(job.stage) ? `: ${openStage(job.stage)}` : ''}${count}...`;
  else line = `${what}: ${job.stage}${count}...`;
  // A copy's rebuild leaves out a run whose output or evidence changed since it ran, which the box names, rather than
  // saying only that the copy is ready
  const left = (job.finished && job.result && job.result.left_out) || [];
  const box = el('div', { class: `start-job${job.error || left.length ? ' failed' : ''}` });
  // A moving mark while the job runs, for the stretch with no count to fill a bar; still under reduced motion
  if (!job.finished) box.append(el('span', { class: 'start-spinner', 'aria-hidden': 'true' }));
  box.append(el('span', { class: 'start-job-line' }, line));
  if (left.length) {
    box.append(
      el('div', { class: 'warn' }, `Its rebuild left out ${plural(left.length, 'run')}, whose output or evidence changed ` +
                                   'since it ran, so their events are not in the copy:'),
      el('ul', { class: 'start-left-out' }, ...left.map((note) => el('li', {}, note))));
  }
  if (job.total && !job.finished) {
    const bar = el('div', { class: 'bar' });
    bar.style.width = `${Math.round((job.done / job.total) * 100)}%`;
    box.append(el('div', { class: 'progress' }, bar));
  }
  return box;
}

function scheduleCheck() {
  clearTimeout(checkTimer);
  checkTimer = setTimeout(async () => {
    const f = START.form;
    try { START.checks = await post('/api/start/check', { evidence: f.evidence, case_folder: f.case_folder, tools: f.tools }); }
    catch (_) { return; }
    for (const key of ['evidence', 'case_folder', 'tools']) {   // update the notes in place, so typing keeps its focus
      const note = $('start').querySelector(`[data-check="${key}"]`);
      const c = START.checks[key];
      if (!note) continue;
      note.className = c ? (c.ok ? 'ok' : 'warn') : '';
      note.textContent = c ? checkNote(key, c) : '';
    }
    const copies = $('start').querySelector('[data-check="evidence-copies"]');
    if (copies) showCopies(copies, START.checks.evidence);
  }, 400);
}

function browseButton(input, key) {
  return startButton('Browse', async () => {
    if (START.browsing && START.browsing.field === key) { START.browsing = null; render(); return; }
    START.browsing = { field: key, input };
    await browseTo(input.value.trim());
  });
}

async function browseTo(path) {
  try { START.browsing.listing = await api(`/api/start/browse?path=${encodeURIComponent(path)}`); }
  catch (err) { setStatus(err.message); return; }
  render();
}

function browser() {
  const b = START.browsing, l = b.listing || { path: '', folders: [] };
  const use = () => {
    if (b.field === 'open') { $('start').querySelector('input[aria-label="Case folder to open"]').value = l.path; }
    else { START.form[b.field] = l.path; if (b.field === 'case_folder') START.caseFolderEdited = true; }
    START.browsing = null;
    render();
    scheduleCheck();
  };
  return el('div', { class: 'start-browser' },
    el('div', { class: 'actions' }, el('span', { class: 'mono' }, l.path || 'This computer'),
      ...(l.parent != null ? [startButton('Up', () => browseTo(l.parent))] : []),
      ...(l.path ? [startButton('Use this folder', use, { class: 'primary' })] : [])),
    ...(l.message ? [el('p', { class: 'muted' }, l.message)] : []),
    el('ul', {}, ...l.folders.map((name) => el('li', {}, startButton(name, () => browseTo(l.path ? `${l.path.replace(/[\\/]$/, '')}\\${name}` : name),
      { class: 'linklike' })))));
}

async function createCase() {
  const f = START.form;
  if (!f.analyst.trim()) { setStatus('Name the analyst.'); return; }
  try { await post('/api/start/new', { name: f.name.trim(), analyst: f.analyst.trim(), evidence: f.evidence.trim(),
                                       case_folder: f.case_folder.trim(), tools: f.tools.trim(), host: f.host }); }
  catch (err) { setStatus(`The case wasn't created: ${err.message}`); return; }
  setStatus('Taking in the evidence...');
  await loadStart();
}

async function copyCase(source, folder, name, analyst) {
  if (!analyst) { setStatus('Name the analyst.'); return; }
  try { await post('/api/start/copy', { source, case_folder: folder, name, analyst }); }
  catch (err) { setStatus(`The copy wasn't made: ${err.message}`); return; }
  START.copying = null;
  setStatus('Copying...');
  await loadStart();
}

// Taking a case whose folder is gone off the list: the server changes recent.json alone, keeps a case whose
// folder is back, and answers with the list as it is now. One at a time: two sent together would each write back the
// list it read, so one removal could come back, and a double click sent a second request that removed nothing.
async function forget(body, name) {
  if (START.forgetting) return;
  START.forgetting = true;
  render();   // the Remove buttons off until the answer
  try {
    const res = await post('/api/start/forget', body);
    START.info.recent = res.recent;
    const back = body.folder && res.recent.some((r) => r.folder === body.folder);
    setStatus(back ? `The folder of ${name} is there again, so it stays on the list.`
      : body.folder ? `Removed ${name} from Recent cases.`
      : res.removed ? `Removed ${plural(res.removed, 'case')} from Recent cases.`
      : 'Nothing removed: no case on the list is missing its folder now.');
  } catch (err) { setStatus(`Not removed: ${err.message}`); }
  finally {
    START.forgetting = false;
    render();
  }
}

async function openCase(folder) {
  if (!folder) { setStatus('Choose a case folder.'); return; }
  setStatus('Opening...');
  try { START.info.job = (await post('/api/start/open', { folder })).job; }
  catch (err) { setStatus(`It didn't open: ${err.message}`); return; }
  render();
  // The open is a job, whose stage the box shows until the timeline opens; one that ended before the answer
  // came back, such as a refusal inside it, is settled at once
  if (START.info.job.finished) settle(START.info.job); else follow();
}

function follow() {
  if (polling) return;
  polling = setInterval(async () => {
    let res;
    try { res = await api('/api/start/job'); } catch (_) { return; }
    START.info.job = res.job;
    render();
    if (!res.job || !res.job.finished) return;
    clearInterval(polling);
    polling = null;
    settle(res.job);
  }, POLL_MS);
}

// What a job that has ended leads to: its error stays in its box, a case that opened takes the page on, and a copy
// is listed.
function settle(job) {
  window.__startJob = job;   // for browser tests
  if (job.error) { setStatus(`Stopped. See the message under ${job.kind === 'open' ? 'Recent cases' : 'New case'}.`); return; }
  if (job.opened) { location.href = job.kind === 'open' ? '/' : '/?page=tools'; return; }
  setStatus(`${job.name} is ready.`);
  loadStart();
}

window.__start = START;   // for browser tests
loadStart();
