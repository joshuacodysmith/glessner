// The Import page: text logs in the evidence folder, such as firewall and IIS logs and CSV
// or JSON-lines exports, become events by a mapping. The server guesses the mapping, checks it on the file's first
// records, and shows the events they become; each change here asks again. An import is a run, recorded with its
// mapping, so a rebuild repeats it. Log text comes from evidence, so it only ever goes in with textContent.

import { api, el, fmtUs, plural, post, setStatus, skippedLinks } from './core.js';
import { button, claimDetails, setPage, showingPage } from './event_page.js';
import { refreshCaseState } from './frame.js';

const I = { meta: null, path: null, checked: new Set(), preview: null, mapping: null, all: false, saveAs: '', busy: false };
const KIND = { w3c_log: 'W3C log', kv_log: 'key=value log', csv: 'CSV', jsonl: 'JSON', line_log: 'log lines' };
const DELIMITERS = [[',', 'comma'], ['\t', 'tab'], [';', 'semicolon'], ['|', 'pipe']];
const SAMPLE_ROWS = 5;
// How much a file holds: a JSON array by its records, which can share one line, and any other file by its lines.
const size = (p) => (p.array_records != null ? plural(p.array_records, 'record') : plural(p.lines, 'line'));

export async function showImport() {
  const latest = claimDetails();   // a page asked for after it keeps the panel
  try { I.meta = await api(`/api/imports${I.all ? '?all=1' : ''}`); }
  catch (err) { setStatus(`Import page failed: ${err.message}`); return; }
  if (!latest()) return;
  // A file loaded as found output from the Tools page, such as an Autoruns CSV, is listed apart and can't be picked:
  // importing it would load its events a second time.
  const files = I.meta.files.filter((f) => !f.loaded);
  if (!files.some((f) => f.path === I.path)) I.path = (files.find((f) => !f.imported) || files[0] || {}).path || null;
  for (const p of [...I.checked]) if (!files.some((f) => f.path === p)) I.checked.delete(p);
  if (I.path) await loadPreview(null); else render();
}

async function loadPreview(mapping) {
  const latest = claimDetails();
  try {
    I.preview = await post('/api/import_preview', { path: I.path, ...(mapping ? { mapping } : {}) });
    I.mapping = I.preview.mapping;
  } catch (err) { I.preview = { error: err.message }; }
  if (latest()) render();
}

function change(edit) {
  const m = structuredClone(I.mapping);
  edit(m);
  delete m.saved_as;   // no longer the saved mapping as it was
  loadPreview(m);
}

function render() {
  setPage('import', [
    el('div', { class: 'imp' }, fileList(), I.path ? mappingPane() :
       el('p', { class: 'muted' }, 'No logs to import yet. Copy them into the evidence folder, then Add new evidence.')),
  ], { title: 'Import', reopen: showImport });
}

function fileList() {
  const rows = I.meta.files.filter((f) => !f.loaded).map((f) => {
    const box = el('input', { type: 'checkbox', 'aria-label': `Import ${f.path} with the same mapping` });
    box.checked = I.checked.has(f.path) || f.path === I.path;
    box.disabled = f.path === I.path;
    box.addEventListener('change', () => { if (box.checked) I.checked.add(f.path); else I.checked.delete(f.path); render(); });
    const done = f.imported ? `imported, ${plural(f.imported.rows || 0, 'event')}` : 'not imported';
    return el('div', { class: `imp-file${f.path === I.path ? ' sel' : ''}` }, box,
      el('div', {}, button(f.path, () => { I.path = f.path; loadPreview(null); }, { class: 'linklike' }),
         el('div', { class: 'muted' }, `${[KIND[f.artifact] || 'Unidentified', f.detail].filter(Boolean).join(', ')}; ${done}`)));
  });
  const all = el('input', { type: 'checkbox' });
  all.checked = I.all;
  all.addEventListener('change', () => { I.all = all.checked; showImport(); });
  const loaded = I.meta.files.filter((f) => f.loaded).map((f) => el('div', { class: 'imp-file' }, el('span'),
    el('div', { class: 'imp-path' }, f.path, el('div', { class: 'muted' }, `${f.detail}; loaded from the Tools page, ` +
                                                       plural(f.loaded.rows || 0, 'event')))));
  return el('div', { class: 'imp-files', 'data-scroll': 'imp-files' },
    el('h3', {}, 'Files to import'), ...rows,
    ...(loaded.length ? [el('h3', {}, 'Loaded as found output'),
                         el('p', { class: 'muted' }, 'Importing these would load their events a second time.'), ...loaded] : []),
    el('label', { class: 'muted' }, all, ' Show other unidentified files'),
    el('div', { class: 'actions' }, button('Add new evidence', addEvidence)),
    el('p', { class: 'muted' }, `Copy logs into the evidence folder, ${I.meta.evidence}, in a host's folder or one of `
       + 'their own, such as FIREWALL. Add new evidence hashes them and lists them here; the import reads them in place.'));
}

async function addEvidence() {
  try {
    const res = await post('/api/evidence_add', {});
    const kinds = Object.entries(res.by_artifact).map(([k, n]) => `${n} ${KIND[k] || k}`).join(', ');
    const gone = res.missing.length;
    setStatus((res.files ? `Added ${plural(res.files, 'new file')} to the manifest (${kinds}).`
                         : 'No new files in the evidence folder.' +
               (gone ? ` ${plural(gone, 'listed file')} ${gone === 1 ? 'is' : 'are'} gone from it; run verify.` : ''))
              + unreadable(res.errors) + skippedLinks(res.links));
    if (showingPage('import')) showImport();   // not over a page asked for while the files were hashed
  } catch (err) { setStatus(`Add new evidence failed: ${err.message}`); }
}

// What Add new evidence could not read, as intake --add prints it: a file or a folder it couldn't open, and a listed
// folder whose files it couldn't look for
function unreadable(errors) {
  if (!errors || !errors.length) return '';
  const shown = errors.slice(0, 3).join('; ') + (errors.length > 3 ? `; and ${errors.length - 3} more` : '');
  return ` Unreadable: ${shown}.`;
}

function mappingPane() {
  const p = I.preview;
  if (p.error) return el('div', {}, el('p', {}, p.error));
  const m = I.mapping;
  const head = el('div', { class: 'actions' }, el('b', {}, p.path),
    el('span', { class: 'muted' }, [p.format_label, p.product !== p.format_label && p.product, size(p)].filter(Boolean).join(', ')),
    el('span', { class: 'muted' }, 'Mapping'), mappingSelect(m));
  return el('div', { class: 'imp-map' }, head, formatRow(m), sampleTable(p, m), settings(p, m), checks(p), eventList(p), importRow(p));
}

function mappingSelect(m) {
  const sel = el('select', { 'aria-label': 'Mapping' },
    el('option', { value: 'guess' }, 'Guessed from the file'),
    el('optgroup', { label: 'Ready-made' }, ...I.meta.presets.map((x) => el('option', { value: `preset:${x.name}` }, x.label))),
    ...(I.meta.saved.length ? [el('optgroup', { label: 'Saved in this case' },
        ...I.meta.saved.map((n) => el('option', { value: `saved:${n}` }, n)))] : []));
  if (m.saved_as) sel.value = `saved:${m.saved_as}`;
  else if (m.preset) sel.value = `preset:${m.preset}`;
  else sel.value = 'guess';
  sel.addEventListener('change', () => {
    const [kind, name] = sel.value.split(':');
    if (kind === 'guess') loadPreview(null);
    else if (kind === 'preset') loadPreview({ preset: name });
    else loadPreview({ saved: name });
  });
  return sel;
}

function formatRow(m) {
  const fmt = el('select', { 'aria-label': 'Format' }, ...Object.entries(I.meta.formats).map(([k, v]) => el('option', { value: k }, v)));
  fmt.value = m.format;
  fmt.addEventListener('change', () => change((x) => { x.format = fmt.value; delete x.delimiter; }));
  const parts = [el('span', { class: 'muted' }, 'Format'), fmt];
  if (m.format === 'csv') {
    const delim = el('select', { 'aria-label': 'Delimiter' }, ...DELIMITERS.map(([d, label]) => el('option', { value: d }, label)));
    delim.value = m.delimiter;
    delim.addEventListener('change', () => change((x) => { x.delimiter = delim.value; }));
    const header = el('input', { type: 'checkbox' });
    header.checked = m.header !== false;
    header.addEventListener('change', () => change((x) => { x.header = header.checked; }));
    parts.push(el('span', { class: 'muted' }, 'Delimiter'), delim, el('label', {}, header, ' The first row names the fields'));
  }
  if (m.format === 'lines') {   // a new layout means new fields, so its ready-made mapping, which has its name
    const layout = el('select', { 'aria-label': 'Layout' }, ...Object.entries(I.meta.layouts).map(([k, v]) => el('option', { value: k }, v)));
    layout.value = m.layout;
    layout.addEventListener('change', () => loadPreview({ preset: layout.value }));
    parts.push(el('span', { class: 'muted' }, 'Layout'), layout);
  }
  return el('div', { class: 'actions' }, ...parts);
}

function roleOf(m, col) {
  if (m.time.columns.includes(col)) return 'time';
  if (m.time.zone_column === col) return 'zone';
  if (m.host.from === 'column' && m.host.column === col) return 'host';
  if (m.ignore.includes(col)) return 'ignore';
  return Object.keys(m.fields).find((r) => m.fields[r] === col) || '';
}

function setRole(col, role) {
  change((m) => {
    m.time.columns = m.time.columns.filter((c) => c !== col);
    if (m.time.zone_column === col) delete m.time.zone_column;
    for (const r of Object.keys(m.fields)) if (m.fields[r] === col) delete m.fields[r];
    m.ignore = m.ignore.filter((c) => c !== col);
    if (m.host.from === 'column' && m.host.column === col) m.host = { from: 'folder' };
    if (role === 'time') {
      const order = I.preview.columns;
      m.time.columns = [...m.time.columns, col].sort((a, b) => order.indexOf(a) - order.indexOf(b));
      m.time.format = '';   // the server guesses it for the new field
    } else if (role === 'zone') m.time.zone_column = col;
    else if (role === 'host') m.host = { from: 'column', column: col, fallback: '' };
    else if (role === 'ignore') m.ignore.push(col);
    else if (role) m.fields[role] = col;
  });
}

function sampleTable(p, m) {
  const roleSelect = (col) => {
    const sel = el('select', { 'aria-label': `What ${col} holds` },
      el('option', { value: '' }, 'Keep as data'), el('option', { value: 'time' }, 'Time'),
      ...Object.entries(I.meta.roles).map(([r, label]) => el('option', { value: r }, label)),
      el('option', { value: 'zone' }, 'Time zone offset'), el('option', { value: 'host' }, 'Host lane'),
      el('option', { value: 'ignore' }, 'Ignore'));
    sel.value = roleOf(m, col);
    sel.addEventListener('change', () => setRole(col, sel.value));
    return sel;
  };
  const rows = p.records.slice(0, SAMPLE_ROWS).map((r) => el('tr', {}, ...p.columns.map((c) => el('td', { title: r.fields[c] ?? '' }, r.fields[c] ?? ''))));
  return el('div', { class: 'imp-scroll', 'data-scroll': 'imp-sample' }, el('table', { class: 'imp-table' },
    el('thead', {}, el('tr', {}, ...p.columns.map((c) => el('th', { class: roleOf(m, c) ? 'mapped' : '' }, roleSelect(c)))),
       el('tr', {}, ...p.columns.map((c) => el('th', { class: 'name' }, c)))),
    el('tbody', {}, ...rows)));
}

function settings(p, m) {
  const grid = el('div', { class: 'imp-settings' });
  const row = (label, ...nodes) => grid.append(el('span', { class: 'muted' }, label), el('span', { class: 'actions' }, ...nodes));

  const fmt = el('select', { 'aria-label': 'Time format' }, el('option', { value: '' }, 'Choose'),
    ...Object.entries(I.meta.time_formats).map(([k, v]) => el('option', { value: k }, v)), el('option', { value: 'custom' }, 'Another format (strptime)'));
  const custom = el('input', { type: 'text', placeholder: '%d.%m.%Y %H:%M:%S', 'aria-label': 'strptime format', size: '22' });
  const known = !m.time.format || m.time.format in I.meta.time_formats;
  fmt.value = known ? m.time.format : 'custom';
  custom.value = known ? '' : m.time.format;
  custom.hidden = known;
  fmt.addEventListener('change', () => { if (fmt.value === 'custom') { custom.hidden = false; custom.focus(); } else change((x) => { x.time.format = fmt.value; }); });
  custom.addEventListener('change', () => change((x) => { x.time.format = custom.value.trim(); }));
  const first = p.events.find((e) => e.ts != null);
  const sample = p.records.length ? m.time.columns.map((c) => p.records[0].fields[c] ?? '').join(' ') : '';
  const year = [];
  if (p.needs_year) {   // syslog, Cisco ASA, and Snort times have no year; the server suggests the case's
    const input = el('input', { type: 'number', min: '1970', max: '2100', 'aria-label': 'Year of the first record', style: 'width:6em' });
    input.value = m.time.year ?? '';
    input.addEventListener('change', () => change((x) => { x.time.year = input.value ? Number(input.value) : ''; }));
    year.push(el('span', { class: 'muted' }, 'Year'), input);
  }
  row('Time', el('span', {}, m.time.columns.length ? m.time.columns.join(' + ') : 'choose a field above'), fmt, custom, ...year,
      el('span', { class: 'muted' }, first ? `${sample} reads as ${fmtUs(first.ts).slice(0, 23)} UTC` : ''));

  const zone = el('select', { 'aria-label': 'Times without a zone are in' }, el('option', { value: '' }, 'Choose: no zone in the file'),
    el('option', { value: 'UTC' }, 'UTC'), ...I.meta.host_zones.map((z) => el('option', { value: z.value }, `${z.label} (the host's zone)`)),
    el('option', { value: 'other' }, 'Another zone or offset'));
  const other = el('input', { type: 'text', list: 'impZones', placeholder: 'Europe/London or -08:00', 'aria-label': 'Zone or offset', size: '22' });
  const zoneKnown = ['', 'UTC', ...I.meta.host_zones.map((z) => z.value)].includes(m.time.zone);
  zone.value = zoneKnown ? m.time.zone : 'other';
  other.value = zoneKnown ? '' : m.time.zone;
  other.hidden = zoneKnown;
  zone.addEventListener('change', () => { if (zone.value === 'other') { other.hidden = false; other.focus(); } else change((x) => { x.time.zone = zone.value; }); });
  other.addEventListener('change', () => change((x) => { x.time.zone = other.value.trim(); }));
  const list = el('datalist', { id: 'impZones' }, ...I.meta.zone_names.map((z) => el('option', { value: z })));
  const resolved = m.time.zone_resolved ? `read as ${m.time.zone_resolved.label}` : '';
  row('Times without a zone are in', zone, other, list, el('span', { class: 'muted' }, m.time.zone_column ? `or the offset in ${m.time.zone_column}; ${resolved}` : resolved));

  const lane = el('select', { 'aria-label': 'Host lane' },
    el('option', { value: 'folder' }, `${p.lane && m.host.from === 'folder' ? p.lane : 'The folder\'s host'} (the folder)`),
    el('option', { value: 'name' }, 'A name'), el('option', { value: 'column' }, 'A field of each record'));
  lane.value = m.host.from;
  lane.addEventListener('change', () => change((x) => {
    x.host = lane.value === 'name' ? { from: 'name', name: x.host.name || 'FIREWALL' }
      : lane.value === 'column' ? { from: 'column', column: p.columns[0], fallback: '' } : { from: 'folder' };
  }));
  const laneParts = [lane];
  if (m.host.from === 'name') {
    const name = el('input', { type: 'text', value: m.host.name, 'aria-label': 'Host lane name', size: '18' });
    name.addEventListener('change', () => change((x) => { x.host.name = name.value.trim(); }));
    laneParts.push(name);
  } else if (m.host.from === 'column') {
    const col = el('select', { 'aria-label': 'Host lane field' }, ...p.columns.map((c) => el('option', { value: c }, c)));
    col.value = m.host.column;
    col.addEventListener('change', () => change((x) => { x.host.column = col.value; }));
    const fallback = el('input', { type: 'text', value: m.host.fallback || '', placeholder: 'lane when empty', 'aria-label': 'Lane for records without a host', size: '16' });
    fallback.addEventListener('change', () => change((x) => { x.host.fallback = fallback.value.trim(); }));
    laneParts.push(col, fallback);
  }
  row('Host lane', ...laneParts);

  const message = el('input', { type: 'text', value: m.message, 'aria-label': 'Message template', class: 'imp-wide',
    placeholder: 'Empty: the first fields as name=value' });
  message.addEventListener('change', () => change((x) => { x.message = message.value; }));
  row('Message', message, el('span', { class: 'muted' }, '{field} for a field; [ ... ] is left out when a field in it is empty'));

  const artifact = el('input', { type: 'text', value: m.artifact, 'aria-label': 'Artifact name', size: '18' });
  artifact.addEventListener('change', () => change((x) => { x.artifact = artifact.value.trim(); }));
  row('Artifact', artifact, el('span', { class: 'muted' }, 'how the Sources panel and filters name these events'));

  const save = el('input', { type: 'text', value: I.saveAs, placeholder: 'palo-alto-traffic', 'aria-label': 'Save mapping as', size: '22' });
  save.addEventListener('input', () => { I.saveAs = save.value.trim(); });
  row('Save mapping as', save, el('span', { class: 'muted' }, 'offered for the next file with the same fields'));
  return grid;
}

function checks(p) {
  return el('div', {}, ...p.problems.map((t) => el('p', { class: 'imp-problem' }, t)),
    ...p.warnings.map((t) => el('p', { class: 'muted' }, t)),
    ...(p.skipped ? [el('p', { class: 'muted' }, p.skipped === 1 ? "1 of the first lines wasn't a record and is skipped."
      : `${p.skipped} of the first lines weren't records and are skipped.`)] : []));
}

function eventList(p) {
  if (!p.events.length) return el('div', {});
  const labels = I.meta.roles;
  return el('div', {}, el('h3', {}, p.events.length === 1 ? 'The first event' : `The first ${plural(p.events.length, 'event')}`),
    el('ul', { class: 'imp-events' }, ...p.events.map((e) => el('li', {},
      el('span', { class: 'time' }, e.ts == null ? '(no time)' : fmtUs(e.ts).slice(0, 23)), el('span', { class: 'host' }, e.host),
      el('span', { class: 'msg' }, e.message),
      el('span', { class: 'muted' }, Object.entries(e.fields).map(([r, v]) => `${labels[r] || r} ${v}`).join(' · '))))));
}

function importRow(p) {
  const paths = [I.path, ...[...I.checked].filter((x) => x !== I.path)];
  const label = paths.length > 1 ? `Import ${paths.length} files` : `Import ${size(p)}`;
  const go = button(I.busy ? 'Importing…' : label, () => runImport(paths), { class: 'primary' });
  if (p.problems.length || I.busy) go.disabled = true;
  const again = p.imported ? ` Imported before (${plural(p.imported.rows ?? 0, 'event')}); importing again replaces them.` : '';
  return el('div', { class: 'actions' }, go, el('span', { class: 'muted' },
    `Recorded as a run, so a rebuild repeats it; the file is read in place and never changed.${again}`));
}

// The Import page again once an import ends, unless the analyst has opened another page since it began
const renderIfShown = () => { if (showingPage('import')) render(); };

async function runImport(paths) {
  I.busy = true;
  render();
  setStatus(`Importing ${paths.length === 1 ? paths[0] : `${paths.length} files`}…`);
  let res;
  try { res = await post('/api/import', { paths, mapping: I.mapping, save_as: I.saveAs }); }
  catch (err) { I.busy = false; renderIfShown(); setStatus(`Import failed: ${err.message}`); return; }
  I.busy = false;
  const ok = res.runs.filter((r) => r.status === 'ok');
  const rows = ok.reduce((n, r) => n + (r.rows || 0), 0);
  const failed = [...res.runs.filter((r) => r.status !== 'ok').map((r) => `${r.path}: ${r.reason}`), ...res.errors.map((e) => `${e.path}: ${e.error}`)];
  if (!ok.length) {
    renderIfShown();
    setStatus(`Import failed. ${failed.join(' ')}`);
    refreshCaseState();   // an import checks its file before and after; a success reloads the page instead
    return;
  }
  setStatus(`Imported ${plural(rows, 'event')} from ${plural(ok.length, 'file')}` +
            (failed.length ? `; failed: ${failed.join(' ')}` : '') + '. Reloading the timeline.');
  window.__imported = res;   // for browser tests
  setTimeout(() => location.reload(), failed.length ? 4000 : 800);
}
