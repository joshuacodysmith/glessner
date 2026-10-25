// The Findings page's right column: the report, the exports, and the files the case wrote. The report
// replaces the findings summary: its Summary is the analyst's paragraph, journaled as the case_setting report_summary;
// Write report (Markdown) is the page's one lead button; Preview shows the text without writing a file. Each export
// states its scope and contents before the click (Marked events cover the whole case; Events in the
// window cover the window shown and the filters when applied; Indicators come from the Malicious marks; the Audit trail
// is the whole journal), and every file written is hashed and journaled, with the head after its entry in the notice.
// Each card's scope and count are the file's: Marked events are the whole case and never filtered; Events in the
// window apply the Sources and View on, which its card counts; the Apply tick is the report's alone. Evidence text
// reaches the page through el() and textContent only.

import { $, api, el, plural, post, reportAction, S, setStatus, windowText } from './core.js';
import { button, headAfter } from './event_page.js';
import { filterCount } from './filters.js';
import { refreshCaseState } from './frame.js';
import { viewCount } from './view.js';

const SUMMARY_MAX = 20000;   // characters, as the server's SUMMARY_MAX

// The filters on now, as the window card and the report's tick name them
const windowFilters = () => { const on = filterCount() + viewCount(); return on ? `, ${plural(on, 'filter')} on` : ''; };
const tickWords = () => (S.filterId ? `Apply the current Sources and View (${filterCount() + viewCount()}) to the report`
  : 'Apply the current Sources and View to the report (none are on)');

// applyFilter calls this when the Sources or the View change, as draw() keeps the window card's window and count: the
// window export applies the filters on at the click, so a change made with the page open would leave the card naming none
// while its file was filtered, and the tick offering filters that were gone
export function renderExportScope() {
  const chip = $('exportWindowFilters'), tick = $('exportFiltered');
  if (chip) chip.textContent = windowFilters();
  if (!tick) return;
  tick.disabled = !S.filterId;
  const label = document.querySelector('label[for=exportFiltered]');
  if (label) label.textContent = tickWords();
}

// Report and Exports each open with the Details band's look, so the column reads as two sections
const sectionBand = (name) => el('h2', { class: 'band details' }, el('span', { class: 'name' }, name));

let newest = null;   // the newest column's state, which summaryDraft reads

// The Summary's text when it isn't the summary as the column read or saved it, for the place a reload puts back; null
// when nothing typed is unsaved. Until the column's first read answers, a draft it was given is still unsaved, with
// what was typed in the box since.
export function summaryDraft() {
  if (!newest || !newest.summary.isConnected) return null;
  if (!newest.loaded) return newest.draft === null ? null : newest.summary.value;
  return newest.summary.value === newest.saved ? null : newest.summary.value;
}

// The column, drawn at once with its controls and filled from /api/exports_page, which every write reads again.
// `summary` is a draft of the Summary's text, kept across a reload or a redraw of the page, which the box shows at once
// in place of the saved one.
export function exportsColumn({ summary = null } = {}) {
  const col = el('section', { class: 'exports-col' });
  const fill = { counts: {}, files: el('div', { class: 'files-box' }), summary: null, loaded: false, saved: '', draft: summary };
  newest = fill;
  const count = (name) => { fill.counts[name] = el('span', { class: 'ex-count' }, '…'); return fill.counts[name]; };
  const reload = async () => {
    let facts;
    try { facts = await api('/api/exports_page'); } catch (err) { setStatus(`Could not read the exports: ${err.message}`); return; }
    const words = (text) => plural(text.trim().split(/\s+/).filter(Boolean).length, 'word');
    const texts = {
      summary: facts.summary ? `written: ${words(facts.summary)}` : 'empty: the report says so',
      findings: `${plural(facts.findings, 'finding')}${facts.retired ? `, ${facts.retired} retired and left out` : ''}, each with its events and what it does not prove`,
      timeline: `${plural(facts.flagged, 'event')} marked Malicious or Suspicious, each with its finding`,
      indicators: `${plural(facts.indicators, 'value')} from ${plural(facts.malicious, 'Malicious mark')}`,
      hosts: `${plural(facts.hosts, 'host')}: roles, names, IPs, offsets`,
      evidence: `re-hashed when written: ${plural(facts.evidence_files, 'file')}; the journal's head`,
      method: `tools, versions, rule sets, ${plural(facts.runs, 'run')}, and the build`,
      marked: `${plural(facts.marked, 'marked event')}, ${facts.flagged.toLocaleString()} of them Malicious or Suspicious`,
      values: `${plural(facts.indicators, 'value')} from ${plural(facts.malicious, 'Malicious mark')}: IPs, domains, hashes, accounts, files, services, tasks`,
      entries: `${plural(facts.journal_entries, 'entry', 'entries')} in plain words`,
    };
    for (const [name, text] of Object.entries(texts)) fill.counts[name].textContent = text;
    if (!fill.loaded) {   // the analyst's text is not overwritten by a later reload
      fill.saved = facts.summary;
      if (fill.draft === null) fill.summary.value = facts.summary;
    }
    fill.loaded = true;
    fill.files.replaceChildren(...writtenFiles(facts));
  };
  const applied = el('input', { type: 'checkbox', id: 'exportFiltered' });
  applied.disabled = !S.filterId;
  const filterBody = () => (applied.checked && S.filterId ? { filter: S.filterId } : {});   // the report's, by its tick
  const filtered = (res) => (res.filter ? ` Filtered: ${res.filter}` : '');
  const result = el('p', { class: 'muted export-result' });
  // One request at a time reports in the result line, with the head after its file's entry; a refusal is the line's too
  const run = async (path, body, said) => {
    try {
      const res = await post(path, body);
      result.replaceChildren(said(res), headAfter(res));
      reportAction(said(res).split(' to ')[0], res.server_ms);
      reload();
      return res;
    } catch (err) { result.textContent = `Not written: ${err.message}`; return null; }
  };
  col.append(...reportSection(count, fill, applied, filterBody, filtered, result, run),
             ...exportsSection(count, filtered, run),
             el('h3', { class: 'written-head' }, 'Written from this case'), fill.files);
  if (summary !== null) fill.summary.value = summary;
  reload();
  return col;
}

// The report: its seven sections with what each holds now, the Summary to write, Write report, and Preview
function reportSection(count, fill, applied, filterBody, filtered, result, run) {
  const item = (name, key) => el('li', {}, el('b', {}, name), ', ', count(key));
  const outline = el('ol', { class: 'report-outline' },
    item('Summary', 'summary'), item('Findings', 'findings'), item('Timeline of marked events', 'timeline'),
    item('Indicators', 'indicators'), item('Hosts and clocks', 'hosts'), item('Evidence and integrity', 'evidence'),
    item('Method', 'method'));
  const summary = el('textarea', { 'aria-label': 'Summary', class: 'report-summary', maxlength: String(SUMMARY_MAX),
                                   placeholder: 'Summary: a paragraph in your words. Left empty, the report says so.' });
  fill.summary = summary;
  const save = button('Save summary', async () => {
    try {
      const res = await post('/api/setting', { name: 'report_summary', value: summary.value });
      summary.value = fill.saved = res.value;
      reportAction(res.value ? 'Saved the report summary' : 'Cleared the report summary', res.server_ms);
      fill.counts.summary.textContent = res.value ? `written: ${plural(res.value.split(/\s+/).filter(Boolean).length, 'word')}`
        : 'empty: the report says so';
    } catch (err) { setStatus(`Summary not saved: ${err.message}`); }
  }, { title: 'Journal the Summary as a case setting. The report prints it as written; empty, the report says so.' });
  const preview = el('pre', { class: 'report-preview', hidden: '' });
  const previewButton = button('Preview', async () => {
    if (!preview.hidden) { preview.hidden = true; previewButton.setAttribute('aria-expanded', 'false'); return; }
    try {
      const res = await api(`/api/report_preview${applied.checked && S.filterId ? `?filter=${S.filterId}` : ''}`);
      preview.textContent = res.text;
      preview.hidden = false;
      previewButton.setAttribute('aria-expanded', 'true');
    } catch (err) { setStatus(`Preview failed: ${err.message}`); }
  }, { 'aria-expanded': 'false', title: 'Show the report as it would be written now. Nothing is written or journaled.' });
  const write = button('Write report (Markdown)', async () => {
    const res = await run('/api/report', filterBody(), (r) => `Wrote the report (${plural(r.events, 'marked event')}) to ${r.path}.${filtered(r)}`);
    if (res) refreshCaseState();   // it re-hashes every evidence file, and the header's line says what that found
  }, { class: 'primary', title: 'Write the report to the case\'s exports folder, hashed and journaled.' });
  return [
    sectionBand('Report'),
    outline,
    el('div', { class: 'report-summary-box' }, summary, el('div', { class: 'actions' }, save)),
    el('div', { class: 'actions' }, applied, el('label', { for: 'exportFiltered' }, tickWords())),
    el('div', { class: 'actions' }, write, previewButton),
    result, preview,
  ];
}

// The exports, each a card that names its scope and contents, then its formats
function exportsSection(count, filtered, run) {
  const marks = el('select', { 'aria-label': 'Which marked events' }, el('option', { value: 'marked' }, 'All marked'),
                   el('option', { value: 'flagged' }, 'Malicious and Suspicious only'));
  const whole = (fmt) => () => run('/api/export', { format: fmt, marks: marks.value },
    (r) => `Wrote ${plural(r.rows, 'event')} to ${r.path}. Whole case.${filtered(r)}`);
  const window = (fmt) => () => {
    const view = { ...S.view };
    return run('/api/export', { start: Math.floor(view.start * 1000), end: Math.ceil(view.end * 1000), format: fmt, marks: 'all', ...(S.filterId ? { filter: S.filterId } : {}) },
               (r) => `Wrote ${plural(r.rows, 'event')} to ${r.path}. Window: ${windowText(view)}.${filtered(r)}`);
  };
  const card = (name, scope, what, ...buttons) => el('div', { class: 'export-card' },
    el('div', { class: 'export-about' }, el('div', {}, el('b', {}, name), ' ', el('span', { class: 'chip scope' }, ...scope)),
       el('div', { class: 'muted export-what' }, ...what)),
    el('div', { class: 'actions export-buttons' }, ...buttons));
  // The events in the window shown, as the state line counts them; draw.js keeps it current as the view moves
  const inWindow = S.windowPending || !S.data ? '…' : `${plural(S.data.count, 'event')} under the current Sources and View`;
  // A CSV's text cells as export.spreadsheet_text writes them; JSONL is written without that change
  const csvCells = 'a tab goes in front of any text a spreadsheet would run as a formula';
  const timelineCells = ` · in CSV, ${csvCells}; JSONL keeps values as written`;
  return [
    sectionBand('Exports'),
    card('Marked events', ['whole case'], [count('marked'), ' · CSV or JSONL with ECS fields, among them a network record\'s signature, community ID, URL, DNS and TLS names, and a DHCP client\'s MAC address · each event\'s mark, note, tags, tool, run, and evidence file', timelineCells],
         marks, button('CSV', whole('csv')), button('JSONL', whole('jsonl'))),
    card('Events in the window', [el('span', { id: 'exportWindow' }, windowText()), el('span', { id: 'exportWindowFilters' }, windowFilters())],
         ['in it now: ', el('span', { id: 'exportWindowCount' }, inWindow), ' · for Timesketch or Timeline Explorer · the window and the filters applied go in the file\'s journal entry', timelineCells],
         button('CSV', window('csv')), button('JSONL', window('jsonl'))),
    card('Indicators', ['Malicious marks'], [count('values'), ' · read from parsed fields only · ', csvCells],
         button('CSV', () => run('/api/indicators', {}, (r) => `Wrote ${plural(r.values, 'indicator value')} from ${plural(r.events, 'Malicious event')} to ${r.path}.`))),
    card('Audit trail', ['whole journal'], [count('entries')],
         button('Markdown', () => run('/api/audit_export', {}, (r) => `Wrote ${plural(r.entries, 'entry', 'entries')} to ${r.path}.`))),
  ];
}

// The files the case wrote (state.files), newest first: when, the file, its rows, and its SHA-256 short with the whole in
// its hover; each is hashed when written and journaled, so a copy handed on can be checked against the case
function writtenFiles(facts) {
  if (!facts.files.length) {
    return [el('p', { class: 'muted' }, 'Nothing written from this case yet. Each file written is hashed and recorded in the journal.')];
  }
  const row = (f) => el('tr', { 'data-seq': String(f.seq) },
    el('td', { class: 'mono', title: `${String(f.at).slice(0, 19).replace('T', ' ')} UTC, by ${f.who} (entry #${f.seq})` }, String(f.at).slice(11, 19)),
    el('td', { title: `${f.path}: ${f.words}` }, String(f.path).split('/').pop()),
    el('td', { class: 'num' }, Number(f.rows).toLocaleString()),
    el('td', {}, el('code', { class: 'journal-head file-hash', title: f.sha256 }, f.short)));
  const more = facts.files_total > facts.files.length
    ? [el('p', { class: 'muted' }, `The newest ${facts.files.length} of ${facts.files_total.toLocaleString()}; the audit trail's Files action lists them all.`)] : [];
  return [
    el('table', { class: 'ov-table files-table' },
      el('thead', {}, el('tr', {}, el('th', {}, 'When (UTC)'), el('th', {}, 'File'), el('th', { class: 'num' }, 'Rows'), el('th', {}, 'SHA-256'))),
      el('tbody', {}, ...facts.files.map(row))),
    ...more,
    el('p', { class: 'muted written-note' }, 'Each file is hashed when written and recorded in the journal, so a copy handed on can be checked against the case.'),
  ];
}
