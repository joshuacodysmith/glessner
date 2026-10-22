// The Tools page: each registry tool's version, what it would read in this case, whether it
// ran, and what's missing; tools' output found in the evidence, such as KAPE's; evidence no installed tool
// reads; and other known tools in the tools folder. A tool runs, or found output loads, from here, one at a time, in
// the background; the page follows it and the timeline reloads after.

import { $, api, el, plural, post, setStatus } from './core.js';
import { button, claimDetails, setPage, showingPage } from './event_page.js';
import { refreshCaseState } from './frame.js';
import { showImport } from './import.js';

const POLL_MS = 1000;
const CHECKING_MS = 250;   // a Tools page that takes longer than this to answer says what it's doing
let polling = null;

// Rows a run or load wrote, as events or, for Hayabusa, as hits, which the timeline doesn't count as events.
const rowsText = (n, hits) => plural(n, hits ? 'Hayabusa hit' : 'event');
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
  if (latest()) render(res, focus);   // unless the analyst opened another page or event meanwhile
  if (res.job && !res.job.finished) follow();
}

function render(res, focus = null) {
  const running = res.job && !res.job.finished;
  const rows = res.tools.map((t) => {
    const hosts = t.hosts.length;
    let status, action = '';
    if (t.status === 'ran') {
      status = el('span', { class: 'ok' }, `Ran ${t.last_run.at.slice(0, 16).replace('T', ' ')} UTC: ${rowsText(t.last_run.rows, t.hits)}`);
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
    return el('tr', {},
      el('td', { title: t.notes }, t.name),
      el('td', {}, ...(t.builtin ? ['built in', el('div', { class: 'muted', title: `glessner ${t.version}` }, '(no download)')]
        : [t.found ? t.version : el('span', { class: 'muted' }, 'not found'), runtimeNote(t)])),
      el('td', {}, t.reads ? `${t.reads}${hosts ? `, on ${plural(hosts, 'host')}` : ''}` : el('span', { class: 'muted' }, 'none')),
      el('td', {}, status), el('td', {}, action));
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
    ...(res.job ? [jobBox(res.job)] : []),
    el('table', { class: 'tools-table' },
      el('thead', {}, el('tr', {}, ...['Tool', 'Version', 'Reads, in this case', 'Status', ''].map((h) => el('th', {}, h)))),
      el('tbody', {}, ...rows)),
    ...(res.outputs.length ? [el('h3', {}, 'Tool output already in the evidence'), outputTable(res.outputs, running)] : []),
    // The latest runs that failed or loaded nothing, which the Case overview's Gaps link to
    ...(res.gaps.length ? [el('h3', {}, 'Runs that failed or loaded nothing'),
      el('ul', { class: 'tools-gaps' }, ...res.gaps.map((g) => el('li', { 'data-run': g.run_id },
        `${g.name} on ${g.host || 'no host'}: ${g.status === 'failed' ? 'failed' : 'ran and loaded nothing'}${g.reason ? `. ${g.reason}` : ''}. `,
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

// Which .NET runtime a framework-dependent tool runs on. A runtime unpacked in the tools folder needs no install.
function runtimeNote(t) {
  if (t.has_rules && t.found) {   // a tool with a rule set beside it, such as Suricata with ET Open
    return el('div', { class: t.rules ? 'muted' : 'warn' }, t.rules ? `Rules: ${t.rules}` : 'No rule set: no rule alerts');
  }
  if (!t.dotnet) return '';
  const net = `.NET ${t.dotnet}`;
  if (!t.found) return el('div', { class: 'muted' }, `Needs ${net}`);
  if (t.dotnet_root) return el('div', { class: 'muted', title: t.dotnet_root }, `${net}, from the tools folder`);
  if (t.version !== 'unknown') return el('div', { class: 'muted' }, `${net}, installed on this computer`);
  return el('div', { class: 'warn' }, `Needs ${net}. Unpack Microsoft's ${net} runtime zip into a folder in the tools folder.`);
}

function jobBox(job) {
  const lines = job.results.map((r) => el('li', {}, `${r.host}: ${r.status}` +
    (r.rows != null ? `, ${rowsText(r.rows, r.hits)}` : '') + `, evidence ${r.evidence}` +
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
      // Events without a time show nowhere else on the page, so the count says so.
      const timeless = g.loaded.without_time ? `, ${g.loaded.without_time.toLocaleString()} without a time, so off the timeline` : '';
      status = el('span', { class: 'ok' }, `Loaded ${g.loaded.at.slice(0, 16).replace('T', ' ')} UTC: ${rowsText(g.loaded.rows || 0, false)}${timeless}`);
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
  try { await post('/api/run_all', {}); }
  catch (err) { setStatus(`Didn't start: ${err.message}`); return; }
  started('Running and loading everything ready...');
}

async function loadOutput(g, anyway) {
  try { await post('/api/load_output', { key: g.key, hosts: [g.host], anyway }); }
  catch (err) { setStatus(`${g.label} didn't load: ${err.message}`); return; }
  started(`Loading ${g.label} on ${g.host}...`);
}

async function runTool(t) {
  try { await post('/api/run_tool', { tool: t.id }); }
  catch (err) { setStatus(`${t.name} didn't start: ${err.message}`); return; }
  started(`Running ${t.name}...`);
}

// A job this page starts is followed at once: a short one can finish before the Tools page answers, and that answer
// shows it finished, not running. Here and when the job finishes, the page draws again only while it shows. The check is
// showingPage('tools'), so a page the analyst asked for keeps the panel once that page has drawn.
function started(text) {
  setStatus(text);
  follow();
  if (showingPage('tools')) showTools();
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
      if (showingPage('tools')) showTools();
      refreshCaseState();   // each run re-hashed the files it read; a load reloads the page, which reads it anyway
    }
  }, POLL_MS);
}
