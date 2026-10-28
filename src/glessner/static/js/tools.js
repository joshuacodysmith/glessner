// The Tools page: each registry tool's version, what it would read in this case, whether it
// ran, and what's missing; tools' output found in the evidence, such as KAPE's; evidence no installed tool
// reads; and other known tools in the tools folder. A tool runs, or found output loads, from here, one at a time, in
// the background; the page follows it and the timeline reloads after.

import { $, api, el, plural, post, sentence, setStatus } from './core.js';
import { askConfirm } from './confirm.js';
import { button, claimDetails, pageAction, pageAnswered, pageRead, setPage } from './event_page.js';
import { refreshCaseState } from './frame.js';
import { showImport } from './import.js';

const POLL_MS = 1000;
const CHECKING_MS = 250;   // a Tools page that takes longer than this to answer says what it's doing
let polling = null;

// Rows a run or load wrote, as events or, for Hayabusa, as hits, which the timeline doesn't count as events.
const rowsText = (n, hits) => plural(n, hits ? 'Hayabusa hit' : 'event');
// What a tool's latest runs loaded (toolbox.overview's last_run): the rows, and the rows without a time and the rows the
// parser skipped when there are any.
const loadedText = (run, hits) => rowsText(run.rows, hits)
  + (run.without_time ? `, ${run.without_time.toLocaleString()} without a time` : '')
  + (run.skipped ? `, ${run.skipped.toLocaleString()} skipped` : '');
// The rule or map sets those runs used, and that a run of a tool that names its set made none to name.
const rulesText = (run) => [...run.rules, ...(run.rules_unrecorded ? ['rules not recorded'] : [])].join('; ');
// What a job's steps are (toolbox.ToolJob): a tool's runs, loads of found output, or both for Run and load everything
// ready. They are not hosts.
const STEPS = { run: ['run', 'runs'], load: ['load', 'loads'], all: ['run or load', 'runs and loads'] };
const stepsText = (job) => `${job.done} of ${job.total} ${(STEPS[job.kind] || STEPS.run)[job.total === 1 ? 0 : 1]}`;

// A running job's step, for its box and the status line: the tool or output and the host, as its step names them.
function jobProgress(job) {
  const at = `(${job.done + 1} of ${job.total})...`;
  if (job.kind === 'all') return `${job.tool}: ${job.current || '...'} ${at}`;
  return `${job.kind === 'load' ? 'Loading' : 'Running'} ${job.tool} on ${job.current || '...'} ${at}`;
}

// `focus` brings a part of the page into view once it draws, as the Case overview's Gaps do: a run, as
// { run: ID }, or the unidentified files, as { unidentified: true }.
export async function showTools(rescan = false, focus = null) {
  if (rescan) setStatus('Scanning the tools folder...');
  // The first open after the server starts, and Scan again, run every tool's version check, which takes a few seconds,
  // so the page says what it is doing while it waits. Opened again, it answers at once.
  let latest = claimDetails();
  const drew = pageRead();
  const checking = setTimeout(() => {
    if (!latest()) return;
    setPage('tools', [el('p', { class: 'muted tools-checking' }, 'Checking the tools folder: '
      + 'each tool reports its version, which takes a few seconds after the app starts or a scan.')],
            { title: 'Tools', reopen: () => showTools() });
    latest = claimDetails();   // setPage claimed the panel for the line; the answer still draws over it
  }, CHECKING_MS);
  let res;
  try { res = await api(`/api/tools${rescan ? '?rescan=1' : ''}`); }
  catch (err) {
    setStatus(`Tools page failed: ${err.message}`);
    const checkingNote = latest() && $('details').querySelector('.tools-checking');   // the line above, if it showed
    if (checkingNote) checkingNote.textContent = `Tools page failed: ${err.message}`;
    return;
  } finally { clearTimeout(checking); }
  if (rescan) setStatus(`Found ${res.found} of ${res.total} tools.`);
  if (latest()) {   // unless the analyst opened another page or event meanwhile
    render(res, focus);
    drew('tools', () => showTools());
  }
  if (res.job && !res.job.finished) follow();
}

function render(res, focus = null) {
  const running = res.job && !res.job.finished;
  const rows = res.tools.map((t) => {
    const hosts = t.hosts.length;
    let status, action = '';
    if (t.status === 'ran') {
      const differed = t.last_run.latest?.check?.result === 'differs' ? '; its tools differed from the pin' : '';
      status = [el('span', { class: 'ok' }, `Ran ${t.last_run.at.slice(0, 16).replace('T', ' ')} UTC: ${loadedText(t.last_run, t.hits)}${differed}`),
        ...(rulesText(t.last_run) ? [el('div', { class: 'muted' }, rulesText(t.last_run))] : [])];
      action = button('Run again', () => runTool(t), { 'aria-label': `Run ${t.name} again` });
    } else if (t.status === 'blocked') {
      status = el('span', { class: 'warn' }, `Can't run here: ${t.missing}`);
    } else if (t.status === 'ready') {
      status = el('span', {}, `Ready, not run${t.work_on_copies ? '. Works on copies of its files.' : ''}`);
      action = button(`Run on ${plural(hosts, 'host')}`, () => runTool(t), { 'aria-label': `Run ${t.name}` });
    } else if (t.status === 'nothing') {
      status = el('span', { class: 'muted' }, 'Nothing in this case for it to read');
    } else {
      const needed = t.status === 'missing';
      status = el('span', { class: needed ? 'warn' : 'muted' },
        needed ? `Not installed. ${t.notes}${t.license ? ` (${t.license})` : ''}` : 'Not installed; nothing in this case for it');
      action = el('a', { href: t.download_url, target: '_blank', rel: 'noopener noreferrer' }, 'Download page');
    }
    if (running && action && action.tagName === 'BUTTON') action.disabled = true;
    const again = t.pin?.state === 'differs' ? pinButton('Pin again', () => pinTools(res, t.pin.group), running, { 'aria-label': `Pin ${t.name} again` }) : null;
    const fold = t.pin?.rows.length ? pinFold(t, res) : null;
    return [el('tr', { 'data-tool': t.id },
      el('td', { title: t.notes }, t.name),
      el('td', {}, ...(t.builtin ? ['built in', el('div', { class: 'muted', title: `glessner ${t.version}` }, '(no download)')]
        : [t.found ? t.version : el('span', { class: 'muted' }, 'not found'), ...runtimeNotes(t), ...(t.pin ? [pinLine(t, fold)] : [])])),
      el('td', {}, t.reads ? `${t.reads}${hosts ? `, on ${plural(hosts, 'host')}` : ''}` : el('span', { class: 'muted' }, 'none')),
      el('td', {}, ...[status].flat()), el('td', {}, ...(again ? [again, ' '] : []), action)),
    ...(fold ? [fold] : [])];
  });
  const unread = [...res.unread.map((u) => el('li', {}, `${u.what}: no installed tool reads them`))];
  // The files the Import page offers to import, counted as it lists them
  if (res.to_import.length) unread.push(el('li', {}, `${res.to_import.join(' and ')}: `, button('open the Import page', () => showImport(), { class: 'linklike' })));
  if (res.unidentified) {
    // Each file with why intake couldn't identify it, where it says, as the CLI's intake summary does
    const list = el('ul', { class: 'tools-unidentified', id: 'toolsUnidentified', hidden: '' }, ...res.unidentified_sample.map((f) =>
      el('li', {}, f.path, ...(f.reason ? [el('span', { class: 'muted' }, ` (${f.reason})`)] : []))));
    unread.push(el('li', {}, `${plural(res.unidentified, 'unidentified file')} `,
      button('List', (ev) => { list.hidden = !list.hidden; ev.currentTarget.textContent = list.hidden ? 'List' : 'Hide'; }, { class: 'linklike' }), list));
  }
  const ready = res.ready.tools.length + res.ready.outputs;
  const all = button('Run and load everything ready', () => runAll(), { title: readyText(res.ready) });
  if (running || !ready) all.disabled = true;
  setPage('tools', [
    el('div', { class: 'actions' }, all, el('span', { class: 'muted' }, ready ? readyText(res.ready) : 'Nothing is ready to run or load.')),
    el('div', { class: 'actions' }, el('span', { class: 'muted' }, `Tools folder ${res.tools_folder || '(not set; PATH only)'}`),
      el('span', { class: 'muted' }, `${res.found} of ${res.total} found`), button('Scan again', () => showTools(true))),
    ...manifestLine(res, running),
    ...(res.job ? [jobBox(res.job)] : []),
    el('table', { class: 'tools-table' },
      el('thead', {}, el('tr', {}, ...['Tool', 'Version', 'Reads, in this case', 'Status', ''].map((h) => el('th', {}, h)))),
      el('tbody', {}, ...rows.flat())),
    ...(res.outputs.length ? [el('h3', {}, 'Tool output already in the evidence'), outputTable(res.outputs, running)] : []),
    // The latest runs that failed or loaded nothing, which the Case overview's Gaps link to
    ...(res.gaps.length ? [el('h3', {}, 'Runs that failed or loaded nothing'),
      el('ul', { class: 'tools-gaps' }, ...res.gaps.map((g) => el('li', { 'data-run': g.run_id },
        `${sentence(`${g.name} on ${g.host || 'no host'}: ${g.status === 'failed' ? 'failed' : 'ran and loaded nothing'}${g.reason ? `. ${g.reason}` : ''}`)} `,
        el('span', { class: 'muted' }, `Run ${g.run_id}, ${g.at.slice(0, 16).replace('T', ' ')} UTC`))))] : []),
    el('h3', {}, 'Evidence no installed tool reads'),
    unread.length ? el('ul', { class: 'tools-unread' }, ...unread) : el('p', { class: 'muted' }, 'Every identified file has a tool.'),
    el('h3', {}, 'Other tools in the tools folder'),
    res.others.length ? el('ul', { class: 'tools-others' }, ...res.others.map((o) => el('li', {}, el('b', {}, o.name), ` ${o.status} `,
      el('span', { class: 'muted' }, `Reads: ${o.reads}.`))))
      : el('p', { class: 'muted' }, 'None that the app knows of.'),
  ], { title: 'Tools', reopen: () => showTools() });
  const target = focus && (focus.run ? $('details').querySelector(`li[data-run="${CSS.escape(focus.run)}"]`)
    : focus.unidentified ? $('toolsUnidentified') : null);
  if (!target) return;
  if (focus.unidentified) {
    target.hidden = false;
    target.previousElementSibling.textContent = 'Hide';   // the list's List button
  }
  target.scrollIntoView({ block: 'nearest' });
  target.classList.add('flash');
  setTimeout(() => target.classList.remove('flash'), 1600);
}

// The lines under a tool's version: the rule or map set it runs with now, and which .NET runtime it runs on.
function runtimeNotes(t) {
  const notes = [];
  if (t.found && t.rules) notes.push(el('div', { class: 'muted' }, `Rules: ${t.rules}`));
  else if (t.found && t.has_rules) notes.push(el('div', { class: 'warn' }, 'No rule set: no rule alerts'));   // such as Suricata without ET Open
  if (t.dotnet) notes.push(dotnetNote(t));
  return notes;
}

// Which .NET runtime a framework-dependent tool runs on. A runtime unpacked in the tools folder needs no install.
function dotnetNote(t) {
  const net = `.NET ${t.dotnet}`;
  if (!t.found) return el('div', { class: 'muted' }, `Needs ${net}`);
  if (t.dotnet_root) return el('div', { class: 'muted', title: t.dotnet_root }, `${net}, from the tools folder`);
  if (t.version !== 'unknown') return el('div', { class: 'muted' }, `${net}, installed on this computer`);
  return el('div', { class: 'warn' }, `Needs ${net}. Unpack Microsoft's ${net} runtime zip into a folder in the tools folder.`);
}

// ---------- Pins: a tool's files against the tools folder's manifest ----------

const openFolds = new Set();   // tools whose fold of pinned files is open, kept across redraws
const utcText = (stamp) => `${stamp.slice(0, 16).replace('T', ' ')} UTC`;
const shortSha = (sha) => `${sha.slice(0, 12)}...`;
const nameList = (names) => (names.length < 3 ? names.join(' and ') : `${names.slice(0, -1).join(', ')}, and ${names.at(-1)}`);

let pinOut = false;   // a confirmed pin is waiting for the server, so a page drawn meanwhile draws its pin buttons held

// A button that pins, disabled while a job runs and, through holdPinButtons, while a pin is out.
function pinButton(label, onclick, running, attrs = {}) {
  const b = button(label, onclick, { class: 'pin-action', ...attrs });
  if (running) b.disabled = true;
  else if (pinOut) holdButton(b);
  return b;
}

// Disable a pin button for the time a pin is out, marking it so releasePinButtons enables it again. A button disabled for
// a running job isn't marked, and stays disabled.
function holdButton(b) {
  b.disabled = true;
  b.dataset.held = '';
}

// Disable the enabled pin buttons on the page, and those the page draws until releasePinButtons, so a second click can't
// open a second confirm or send a second pin while one is out.
function holdPinButtons() {
  pinOut = true;
  for (const b of $('detailsBody').querySelectorAll('button.pin-action:not(:disabled)')) holdButton(b);
}

// Enable the pin buttons that holdPinButtons or a page drawn while the pin was out disabled, once the server has answered.
function releasePinButtons() {
  pinOut = false;
  for (const b of $('detailsBody').querySelectorAll('button.pin-action[data-held]')) {
    b.disabled = false;
    delete b.dataset.held;
  }
}

// The line under a tool's version: the badge, with its hover, and the toggle that opens the fold of pinned files.
function pinLine(t, fold) {
  const children = [el('span', { class: `pin-badge ${t.pin.tone}`, title: t.pin.hint }, t.pin.label)];
  if (fold) {
    const toggle = button('Pinned files', () => {
      fold.hidden = !fold.hidden;
      toggle.setAttribute('aria-expanded', String(!fold.hidden));
      if (fold.hidden) openFolds.delete(t.id); else openFolds.add(t.id);
    }, { class: 'linklike', 'aria-expanded': String(openFolds.has(t.id)) });
    children.push(' ', toggle);
  }
  return el('span', { class: 'pin-line' }, ...children);
}

// A path's pinned hash, or "none" for a path the pin doesn't hold. The whole hash is its hover.
const hashCell = (sha) => el('td', { class: `pin-sha${sha ? '' : ' muted'}`, title: sha }, sha ? shortSha(sha) : 'none');

function nowWords(r) {
  if (r.state === 'same') return 'Matches';
  if (r.state === 'missing') return 'Missing, possibly removed by antivirus';
  if (r.state === 'changed' && r.detail) return `Differs: ${r.detail}`;
  return `${r.state === 'added' ? 'Added' : 'Changed'}, now ${shortSha(r.now)}`;
}

function pinRow(r) {
  if (r.state === 'more') return el('tr', { class: 'pin-more muted' }, el('td', { colspan: '3' }, `and ${r.more.toLocaleString()} more`));
  return el('tr', { class: `pin-row${r.depth ? ' nested' : ''}` }, el('td', { class: 'pin-path' }, r.path), hashCell(r.pinned),
    el('td', { class: `pin-now ${r.state === 'same' ? 'ok' : 'warn'}` }, nowWords(r)));
}

// The links a tool's folder holds that the pin and the folder now agree on or not.
function linkLine(rows) {
  if (!rows.length) return el('div', { class: 'muted' }, 'Links: none pinned, none now.');
  const words = {
    same: (l) => `${l.path} -> ${l.pinned}: matches`,
    changed: (l) => `${l.path}: pointed to ${l.pinned} when pinned, now ${l.now}`,
    missing: (l) => `${l.path} -> ${l.pinned}: missing now`,
    added: (l) => `${l.path} -> ${l.now}: not in the pin`,
  };
  return el('div', {}, 'Links:', el('ul', { class: 'pin-links' }, ...rows.map((l) => el('li', {}, words[l.state](l)))));
}

// The full-width row under a tool's row: when and by what the pin was made, each pinned file or folder with its pinned hash
// and what it is now, the links, the manifest, and the tool's latest run in this case.
function pinFold(t, res) {
  const { pinned, rows, link_rows: links } = t.pin;
  const latest = t.last_run?.latest;
  const manifest = res.manifest;
  const intro = `Pinned ${utcText(pinned.utc)} by build ${pinned.by}, at version ${pinned.version}`
    + `${pinned.rules ? ` with ${pinned.rules}` : ''}.`;
  return el('tr', { class: 'pin-fold', 'data-tool': t.id, ...(openFolds.has(t.id) ? {} : { hidden: '' }) },
    el('td', { colspan: '5' },
      el('div', {}, intro),
      el('table', { class: 'pin-table' },
        el('thead', {}, el('tr', {}, ...['Pinned file or folder', 'Pinned SHA-256', 'Now'].map((h) => el('th', {}, h)))),
        el('tbody', {}, ...rows.map(pinRow))),
      linkLine(links),
      el('div', { class: 'muted' }, `Tools manifest ${manifest.path}, SHA-256 `,
        el('span', { title: manifest.sha256 }, shortSha(manifest.sha256)), '.'),
      el('div', { class: 'muted' }, latest ? `Latest run, ${utcText(latest.at)} on ${latest.host}: ${latest.text}.`
        : 'No run of this tool in this case.')));
}

// The manifest's line, with the button that pins every tool that has no pin, and the place the confirm opens.
function manifestLine(res, running) {
  const m = res.manifest;
  if (!m?.path) return [];
  const more = m.unpinned.length ? [pinButton('Pin unpinned tools', () => pinTools(res, m.unpinned), running)] : [];
  return [el('div', { class: 'actions tools-manifest' },
    el('span', { class: m.state === 'unreadable' ? 'warn' : 'muted' }, `Tools manifest ${m.path}: ${sentence(m.text)} Checked at ${m.checked.slice(11, 16)} UTC.`), ...more),
  el('div', { class: 'confirm-slot' })];
}

// Ask first, then pin the named tools with the files the page showed. The server refuses when a file changed since, and
// says to scan again.
async function pinTools(res, ids) {
  const tools = ids.map((id) => res.tools.find((t) => t.id === id));
  const names = nameList(tools.map((t) => t.name));
  const changed = tools.filter((t) => t.pin.changes);
  const ok = await askConfirm({
    title: `Pin ${names} as ${tools.length === 1 ? 'it is' : 'they are'} now, in ${res.manifest.path}? `
      + 'Every case that uses this tools folder compares with its pins.',
    lines: [...changed.map((t) => `${changed.length > 1 ? `${t.name}, since` : 'Since'} its pin of ${t.pin.pinned.utc.slice(0, 10)}: ${t.pin.changes}.`),
      "A pin records what is in the folder; it doesn't check where the files came from."],
    confirm: `Pin ${names}`,
  });
  if (!ok) return;
  const done = pageAction('tools');
  const pins = Object.fromEntries(tools.map((t) => [t.id, { executable: t.pin.executable, files: t.pin.files, links: t.pin.links }]));
  holdPinButtons();
  try { await post('/api/pin_tools', { tools: pins }); }
  catch (err) {
    releasePinButtons();
    setStatus(`Didn't pin: ${err.message}`);
    return;
  }
  pinOut = false;   // the buttons held stay disabled until the page the pin changed draws again
  setStatus(`Pinned ${names}.`);
  done();
}

function jobBox(job) {
  const lines = job.results.map((r) => el('li', {}, `${r.host}: ${r.status}` +
    (r.rows != null ? `, ${rowsText(r.rows, r.hits)}` : '') + `, evidence ${r.evidence}` +
    (r.tool_check === 'differs' ? ', tools differ from the pin' : '') +
    (r.working_copy_changes ? '; it changed its working copies, as expected' : '') + (r.reason ? `. ${r.reason}` : '')));
  const head = job.finished ? `${job.tool} finished ${stepsText(job)}.` : jobProgress(job);
  return el('div', { class: `tools-job${job.error ? ' failed' : ''}` }, el('div', {}, head),
    ...(job.error ? [el('div', {}, job.error)] : []), ...(lines.length ? [el('ul', {}, ...lines)] : []));
}

// Output that other tools made, found in the evidence. Raw evidence comes first: output for a host whose
// raw files an installed tool reads waits behind Load anyway.
function outputTable(outputs, running) {
  const rows = outputs.map((g) => {
    let status, action = '';
    const what = plural(g.files, 'file');
    if (g.status === 'loaded') {
      // Events without a time show nowhere else on the page, so the count says so, and so does the count of rows skipped.
      const timeless = g.loaded.without_time ? `, ${g.loaded.without_time.toLocaleString()} without a time, so off the timeline` : '';
      const skipped = g.loaded.skipped ? `, ${g.loaded.skipped.toLocaleString()} skipped` : '';
      status = el('span', { class: 'ok' }, `Loaded ${g.loaded.at.slice(0, 16).replace('T', ' ')} UTC: ${rowsText(g.loaded.rows || 0, false)}${timeless}${skipped}`);
    } else if (g.status === 'ready') {
      status = el('span', {}, 'Ready, not loaded');
      action = button('Load', () => loadOutput(g, false), { 'aria-label': `Load ${g.label} on ${g.host}` });
    } else if (g.status === 'raw') {
      status = el('span', { class: 'muted' }, `Not loaded: ${g.tool_name} runs on the raw files instead`);
      action = button('Load anyway', () => loadOutput(g, true), { 'aria-label': `Load ${g.label} on ${g.host} anyway` });
    } else if (g.status === 'no_host') {
      status = el('span', { class: 'muted' }, "In the evidence folder's top level, which belongs to no host");
    } else {
      status = el('span', { class: 'muted' }, g.note || 'No parser yet');
    }
    if (running && action && action.tagName === 'BUTTON') action.disabled = true;
    return el('tr', {}, el('td', { title: g.paths.join('\n') }, g.label), el('td', {}, g.tool_name),
      el('td', {}, g.host ? `${what}, on ${g.host}` : what), el('td', {}, status), el('td', {}, action));
  });
  return el('table', { class: 'tools-table tools-outputs' },
    el('thead', {}, el('tr', {}, ...['Output', 'Made by', 'Holds', 'Status', ''].map((h) => el('th', {}, h)))),
    el('tbody', {}, ...rows));
}

// The one-folder-in path: every tool that has evidence here and hasn't run, then every ready group of found
// output, in one background job. Raw evidence comes first, so the tools run before any output loads.
function readyText(r) {
  const parts = [];
  if (r.tools.length) parts.push(`run ${r.tools.join(', ')}`);
  if (r.outputs) parts.push(`load ${plural(r.outputs, 'group')} of found output`);
  return parts.length ? `Will ${parts.join(', then ')}.` : '';
}

async function runAll() {
  const done = pageAction('tools');
  try { await post('/api/run_all', {}); }
  catch (err) { setStatus(`Didn't start: ${err.message}`); return; }
  started('Running and loading everything ready...', done);
}

async function loadOutput(g, anyway) {
  const done = pageAction('tools');
  try { await post('/api/load_output', { key: g.key, hosts: [g.host], anyway }); }
  catch (err) { setStatus(`${g.label} didn't load: ${err.message}`); return; }
  started(`Loading ${g.label} on ${g.host}...`, done);
}

async function runTool(t) {
  const done = pageAction('tools');
  try { await post('/api/run_tool', { tool: t.id }); }
  catch (err) { setStatus(`${t.name} didn't start: ${err.message}`); return; }
  started(`Running ${t.name}...`, done);
}

// A job this page starts is followed at once: a short one can finish before the Tools page answers, and that answer
// shows it finished, not running. The page draws again when the server has taken the job (`done`, pageAction's, noted as
// the request went out) and when the job finishes with nothing loaded (pageAnswered). Neither draws over a page asked for
// since, even one still loading, and a page asked for before the Tools page drew does not count.
function started(text, done) {
  setStatus(text);
  follow();
  done();
}

function follow() {
  if (polling) return;
  polling = setInterval(async () => {
    let res;
    try { res = await api('/api/run_status'); } catch (_) { return; }
    const job = res.job;
    if (!job) return;
    setStatus(job.finished ? `${job.tool} finished.` : `Working: ${jobProgress(job)}`);
    if (!job.finished) return;
    clearInterval(polling);
    polling = null;
    const sum = (hits) => job.results.reduce((n, r) => n + (r.status === 'ok' && !!r.hits === hits ? r.rows || 0 : 0), 0);
    const events = sum(false), hits = sum(true);
    if ((events || hits) && !job.error) {
      const loaded = [...(events || !hits ? [rowsText(events, false)] : []), ...(hits ? [rowsText(hits, true)] : [])];
      setStatus(`${job.tool} loaded ${loaded.join(' and ')}. Reloading the timeline.`);
      setTimeout(() => location.reload(), 1500);
    } else {
      pageAnswered('tools');
      refreshCaseState();   // each run re-hashed the files it read; a load reloads the page, which reads it anyway
    }
  }, POLL_MS);
}
