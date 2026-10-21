// Search: find events by text across every field. The server saves each search's matches,
// so adding a search to the view filter shows them all on the timeline without searching again. The syntax is in
// SEARCH_HELP and search.py, with worked examples on the Search help page. Results say where the matches
// are: a strip of match counts over time, the busiest stretch, every match marked on the timeline,
// the search terms highlighted, and the field a word was found in.

import { $, api, codePrefix, el, fmtUs, marked, plural, reportAction, S, setHighlight, setStatus } from './core.js';
import { animateView } from './data.js';
import { draw } from './draw.js';
import { button, claimDetails, setPage, showingPage } from './event_page.js';
import { filterParam } from './filters.js';
import { markableList, stickUnder } from './pages.js';
import { addViewValue, describeValue, viewToggle } from './view.js';

export const SEARCH_HELP = 'Words match anywhere, in any letter case, and all must match. "nmap" or "a phrase" in quotes matches whole ' +
  'words only, so "nmap" finds nmap.exe and not WinMaps. ' +
  'field:value matches a whole value in any letter case, with * for any text: ip:10.42.85.10, user:*admin*, code:4624, or an event data ' +
  'name such as ProcessName:*\\cmd.exe. -word excludes. Press / to search from anywhere on the page. ' +
  'The ? button beside the box has examples.';

// The Search help page: the fields search knows (search.py and filters.py), and examples to run with a click.
const HELP_FIELDS = [
  ['code', 'Event ID or code', 'code:4624'], ['channel', 'Event log channel', 'channel:*sysmon*'],
  ['provider', 'Event provider', 'provider:*PowerShell*'], ['user', 'Account, DOMAIN\\name or the name alone', 'user:administrator'],
  ['ip', 'Source IP (also src)', 'ip:10.42.85.10'], ['port', 'Source port (also sport)', 'port:51544'],
  ['dest_ip', 'Destination IP (also dst)', 'dest_ip:10.0.0.9'], ['dest_port', 'Destination port (also dport)', 'dest_port:3389'],
  // Older Sysmon records an inbound connection's remote address as the destination
  ['addr', 'An IP at either end: what ip: or dst: would find, such as an inbound connection\'s remote address', 'addr:10.42.85.10'],
  ['host', 'Host lane', 'host:DC01'], ['computer', 'Computer name the event recorded', 'computer:*DC01*'],
  ['logon_type', 'Logon type', 'logon_type:10'], ['logon_id', 'Logon ID', 'logon_id:0x510986'],
  ['workstation', 'Source workstation', 'workstation:DESKTOP*'], ['process', 'Process path', 'process:*\\powershell.exe'],
  ['command_line', 'Command line (also cmd)', 'command_line:*-enc*'],
  ['parent', 'Parent process path (also parent_process)', 'parent:*\\w3wp.exe'],
  ['parent_command_line', 'Parent command line (also parent_cmd)', 'parent_command_line:*DcomLaunch*'],
  ['path', 'File path; a full path also finds the file in the MFT, Prefetch, and event logs, as Same file does', 'path:*\\Temp\\*'],
  ['registry_key', 'Registry key (also key)', 'registry_key:*\\Run'], ['registry_value', 'Registry value name', 'registry_value:*'],
  ['registry_data', 'Registry value data', 'registry_data:*.dll'],
  ['artifact', 'Artifact: evtx, mft, prefetch, lnk, registry, shellbags, amcache, jumplist, srum, recycle_bin, autoruns, or an import\'s name',
   'artifact:amcache'],
  ['rule', 'A Hayabusa rule title: the events the rule hit', 'rule:"*Mimikatz*"'],
  ['tool', 'Tool that read it', 'tool:evtxecmd'], ['file', 'Source file, relative to the evidence folder', 'file:*Security.evtx'],
];
const HELP_EXAMPLES = [
  ['Sysmon network connections', 'code:3 channel:*sysmon*'],
  ['Sysmon process starts running PowerShell', 'code:1 channel:*sysmon* process:*\\powershell.exe'],
  ['RDP logons', 'code:4624 logon_type:10'],
  ['An account\'s logons, without its special logons', 'user:administrator -code:4672'],
  ['A phrase, as whole words', '"was successfully logged on"'],
  ['A word anywhere, with a wildcard', 'mimi*'],
  ['An event data field by its own name', 'TargetUserName:*$'],
];

export function setupSearch() {
  const box = $('search');
  box.title = SEARCH_HELP;
  box.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' && box.value.trim()) typeSearch(box.value.trim()); });
  $('searchHelp').addEventListener('click', showSearchHelp);
  document.addEventListener('keydown', (ev) => {
    const typing = ev.target.closest && ev.target.closest('input, textarea, select, [contenteditable]');
    if (ev.key === '/' && !typing && !ev.ctrlKey && !ev.metaKey && !ev.altKey) { ev.preventDefault(); box.focus(); box.select(); }
  });
}

// Adds a field:value term to the search box, quoted when it needs to be. The analyst presses Enter to run it.
export function addToSearch(field, value) {
  const box = $('search');
  const term = searchTerm(field, value);
  box.value = `${box.value.trim()} ${term}`.trim();
  box.focus();
  setStatus(`Added ${term} to the search box; press Enter to search.`);
}

// A field:value term as the search box reads it, the value in quotes when it needs them
export function searchTerm(field, value) {
  return `${field}:${/[\s"]/.test(value) || value.startsWith('-') ? `"${value}"` : value}`;
}

// A search the analyst asks for, typed or taken from the help's examples, starts a new trail. The band shows the trail on
// every page, so the old one would otherwise stay in view under a search that has nothing to do with it.
function typeSearch(q) { S.trail = []; S.trailAt = -1; showSearch(q); }
function run(q) { $('search').value = q; typeSearch(q); }
export const typedSearch = run;   // for a link elsewhere that asks for a search, such as the overview's rule titles
// Runs a search for a next pivot that is one (the Event page), which is a step of the trail
export function runSearch(q) { $('search').value = q; showSearch(q); }

export function showSearchHelp() {
  setPage('searchHelp', [
    el('h2', {}, 'Search help'),
    el('p', {}, 'Type words, phrases, and field:value terms in the search box, then press Enter. Every term must match.'),
    el('table', { class: 'help-table' },
      el('tr', {}, el('td', {}, 'word'), el('td', {}, 'The word anywhere in the event, in any letter case, even inside another word; * stands for any text')),
      // Quotes mean whole words: the Whole word tick over the results adds or takes them off
      el('tr', {}, el('td', {}, '"word" or "a phrase"'), el('td', {}, 'Whole words only, in any letter case: "nmap" finds nmap.exe and not WinMaps, and "logged on" does not find ' +
        '"blogged on". A letter a to z, a digit, or an underscore touching either end of the match rules it out. The Whole word box over ' +
        'the results adds the quotes to every word of the search, or takes them off. An accented letter is not a word character.')),
      // An address compares in the Event page's shortened form, so the help says how to type one.
      el('tr', {}, el('td', {}, 'field:value'), el('td', {}, 'A whole field value, in any letter case; * for any text. Quote a value with spaces. ' +
        'An IP address in ip:, dst:, or addr: matches as the Event page shows it: type IPv6 shortened, as fe80::1.')),
      el('tr', {}, el('td', {}, 'Name:value'), el('td', {}, 'An event data field by its own name, as listed on the Event page, such as ProcessName or TargetUserName')),
      el('tr', {}, el('td', {}, '-term'), el('td', {}, 'Leaves out events that match the term'))),
    el('h3', {}, 'Examples'),
    el('ul', { class: 'help-examples' }, ...HELP_EXAMPLES.map(([what, q]) =>
      el('li', {}, button(q, () => run(q), { class: 'linklike mono' }), el('span', { class: 'muted' }, ` ${what}`)))),
    el('h3', {}, 'Fields'),
    el('table', { class: 'help-table' }, ...HELP_FIELDS.map(([name, what, q]) =>
      el('tr', {}, el('td', {}, name), el('td', {}, what), el('td', {}, button(q, () => run(q), { class: 'linklike mono' }))))),
    el('p', { class: 'muted' }, 'On the Event page, Add to search beside a field puts its field:value in the search box. ' +
       'Marks, host roles, and tags change as you work, so they are in the View filter and the Lanes selector, not in search.'),
  ], { title: 'Search help', reopen: showSearchHelp });
}

// `quiet` draws the search again after a mark, which keeps the mark's line in the status bar.
export async function showSearch(q, quiet = false) {
  if (!S.searchChecked || S.searchChecked.q !== q) S.searchChecked = { q, set: new Set() };
  if (!quiet) setStatus(`Searching for ${q}...`);
  const page = { key: `search:${q}`, title: `Search: ${q}`, reopen: () => showSearch(q) };
  // A search that answers after the analyst asked for an event or another page draws nothing.
  const latest = claimDetails();
  let res;
  try { res = await api(`/api/search?q=${encodeURIComponent(q)}${filterParam()}`); }
  catch (err) {
    if (!latest()) return;
    setPage('search', [el('h2', {}, 'Search'), el('p', {}, err.message), el('p', { class: 'muted' }, SEARCH_HELP)], page);
    reportAction(`Search failed: ${err.message}`);
    return;
  }
  if (!latest()) return;
  setHighlight(res.highlight);
  S.related = new Set(res.uids || res.events.map((e) => e.uid));   // every match stands out on the timeline
  draw();
  render(q, res, page);
  if (!quiet) reportAction(`Search: ${plural(res.total, 'matching event')}`, res.server_ms);
}

const zoomTo = (a, b) => {
  const pad = (b - a) / 1000 * 0.05 + 1000;
  animateView(a / 1000 - pad, b / 1000 + pad);
};

function strip(res) {
  const { start, width, counts } = res.strip;
  const max = Math.max(...counts), end = start + width * counts.length;
  const bars = counts.map((n, i) => {
    const a = start + i * width, b = a + width;
    const bar = el('span', { class: `bar${n ? '' : ' empty'}`,
      title: n ? `${plural(n, 'match', 'matches')}, ${fmtUs(a).slice(0, 16)} to ${fmtUs(b).slice(0, 16)} UTC. Click to zoom there.` : '' });
    bar.style.height = n ? `${Math.max(3, Math.round((n / max) * 30))}px` : '1px';
    if (n) bar.addEventListener('click', () => zoomTo(a, b));
    return bar;
  });
  return el('div', { class: 'match-strip-box' },
    el('div', { class: 'match-strip', role: 'img', 'aria-label': 'Matches over time; click a bar to zoom there' }, ...bars),
    el('div', { class: 'match-strip-ends muted' }, el('span', {}, fmtUs(start).slice(0, 16)), el('span', {}, `${fmtUs(end).slice(0, 16)} UTC`)));
}

// The Whole word tick: quotes mean whole words, and the tick quotes every free-text word of the search or
// takes the quotes off. The server rewrites the query (search.whole_word), so the page has no tokenizer of its own. Checked
// when every word is in quotes, part-checked when some are; a phrase with spaces stays whole words either way.
function wholeWordTick(res) {
  const ww = res.whole_word;
  if (!ww) return [];
  const box = el('input', { type: 'checkbox' });
  box.checked = ww.state === 'all';
  box.indeterminate = ww.state === 'some';
  box.addEventListener('change', () => run(box.checked ? ww.on : ww.off));
  const phrase = /(^|\s)-?"[^"]*\s[^"]*"/.test(res.query);   // a quoted phrase with spaces, not a field's value
  return [el('label', { class: 'whole-word', title: 'Whole words only: "nmap" finds nmap.exe and not WinMaps' +
                                                 (phrase ? '. A phrase in quotes stays whole words.' : '') }, box, ' Whole word')];
}

// The event cell of a result row: the code, the message with its matches marked, and where a word was found
function row(e) {
  const nodes = [codePrefix(e), ...marked(e.msg)];
  if (e.found) {
    nodes.push(el('span', { class: 'found' }, ` in ${e.found.field}: ${e.found.before ? '…' : ''}`, ...marked(e.found.text),
                  e.found.after ? '…' : ''));
  }
  return nodes;
}

function render(q, res, page) {
  const checked = S.searchChecked.set;
  const rerender = () => render(q, res, page);
  // The find box reaches the listed rows; on a list cut at the limit, its line offers the search again with the
  // find's words added, over every match
  const find = { page: page.key, name: 'results', covers: 'The count and the timeline still cover',
                 listed: res.limited ? res.events.length : null, total: res.total, searchAll: (text) => run(`${q} ${text}`) };
  const { buttons, list, find: finder } = markableList(res.events, checked, rerender, () => showSearch(q, true), {
    label: row, highlight: marked, offsets: false, via: true, hiddenTag: 'hidden by the View', find });
  const hidden = S.viewSpec ? res.events.filter((e) => !e.shown).length : 0;
  const span = res.total ? `, ${fmtUs(res.first).slice(0, 19)} to ${fmtUs(res.last).slice(0, 19)} UTC` : '';
  const core = res.core;
  const busiest = core && res.total > 1 ? [button('Zoom to the busiest stretch', () => zoomTo(core.start, core.end), {
    class: 'linklike', title: `The shortest stretch holding half the matches: ${core.count.toLocaleString()} of ${res.total.toLocaleString()}, ` +
           `${fmtUs(core.start).slice(0, 19)} to ${fmtUs(core.end).slice(0, 19)} UTC` })] : [];
  // The count line and the buttons stay at the panel's top while the list scrolls. The Details band names the
  // search, so the head has no heading of its own.
  const head = el('div', { class: 'sticky-head' },
    el('div', { class: 'actions' }, ...wholeWordTick(res),
      el('strong', {}, `${plural(res.total, 'matching event')}${span}`),
      ...(S.viewSpec ? [el('span', { class: 'muted', id: 'searchHidden' }, `${hidden.toLocaleString()} listed are hidden by the View`)] : []),
      ...(res.total ? [...buttons,
        viewToggle({ search: res.query }, { name: 'this search', className: '' }),
        ...busiest, button('Fit to all of them', () => zoomTo(res.first, res.last), { class: 'linklike' }), finder.box] : [])));
  // The rows the View hides, and what of the View hides them: an event shows when it meets any of the View's terms, so
  // these meet none. The button adds this search to the View, so its matches show beside the View's own.
  const why = hidden && res.view_terms.length
    ? [el('p', { class: 'muted', id: 'searchHiddenWhy' }, `The View shows only events ${res.view_terms.join('; or ')}. ` +
          'The rows marked "hidden by the View" meet none of that.', ' ',
        button('Show the hidden matches on the timeline', async () => {
          await addViewValue({ search: res.query });   // this search only: the View's other terms stay as they were
          if (showingPage(page.key)) showSearch(q);
        }, { id: 'searchShowHidden', title: 'Add this search to the View, so its matches show on the timeline; Remove this search from view filter undoes it' }))] : [];
  stickUnder(list, head);
  const adds = forgivingLine(res, page, rerender);
  // The rules found by name are under the results, out of sight of a long list, so the strip's row says they are there: a
  // link beside the strip, or alone after the count line when the search has no strip
  const named = res.total && res.by_name ? res.by_name : [];
  const found = named.length ? [byNameLink(named, head)] : [];
  const stripRow = res.strip && res.total > 1 ? [el('div', { class: 'strip-row' }, strip(res), ...found)]
    : found.length ? [el('div', { class: 'strip-row' }, ...found)] : [];
  setPage('search', [
    el('div', { class: 'related' }, head, el('p', { class: 'reach' }, `Looking for ${res.terms.join('; and ')}.`, ...adds.offer),
      ...adds.result, ...why,
      ...stripRow,
      ...(res.uids_limited ? [el('p', { class: 'muted' }, `The timeline marks the first ${res.uids.length.toLocaleString()} matches.`)] : []),
      ...(res.limited ? [el('p', { class: 'muted' }, `Listing the first ${res.events.length} in time order. ` +
                                                    'Add this search to the view filter to see them all on the timeline.')] : []),
      // A cut list's find line goes over the list, where its reach is read before the rows; an uncut one's under it
      ...(res.total ? [...(res.limited ? [finder.foot, list] : [list, finder.foot]), ...byName(res, checked, rerender, q)]
        : res.hint ? zeroHint(res) : [el('p', {}, 'No event matches.'), el('p', { class: 'muted' }, SEARCH_HELP)])),
  ], page);
}

// The forgiving-search line: what the search would find without the quotes of its first quoted word. It costs
// a scan of its own, so it waits for a click. Kept here, by page, so a tick that redraws the page keeps it.
let forgiving = null;   // { key, busy } while the server counts, { key, res } when it has
const FORGIVING_TITLE = 'Runs the forgiving search once and groups the words it matched inside; a second scan, so it waits for the click';

function forgivingLine(res, page, rerender) {
  if (!res.forgiving || !res.whole_word || res.whole_word.state === 'none') return { offer: [], result: [] };
  const mine = forgiving && forgiving.key === page.key ? forgiving : null;
  if (mine && mine.busy) return { offer: [' ', el('span', { id: 'searchAddsBusy' }, 'Counting…')], result: [] };
  if (!mine) {
    const count = async () => {
      const state = forgiving = { key: page.key, busy: true };
      // Only this request's own state goes: the analyst may have left and asked for another page's count meanwhile
      const drop = () => { if (forgiving === state) forgiving = null; };
      rerender();
      let out;
      try { out = await api(`/api/search_adds?q=${encodeURIComponent(res.query)}`); }
      catch (err) {
        drop();
        if (showingPage(page.key)) { rerender(); setStatus(`The forgiving search didn't run: ${err.message}`); }
        return;
      }
      if (!showingPage(page.key)) { drop(); return; }   // the analyst went elsewhere while it counted
      forgiving = { key: page.key, res: out };
      reportAction(`Counted what the forgiving search adds: ${plural(out.total, 'event')}`, out.server_ms);
      rerender();
    };
    return { offer: [' ', button('Show what the forgiving search adds', count, { class: 'linklike', id: 'searchAddsGo', title: FORGIVING_TITLE })],
             result: [] };
  }
  const r = mine.res;
  const groups = r.groups.flatMap((g, i) => [i ? ' · ' : '', button(`${g.word} ${g.count.toLocaleString()}`, () => run(g.query),
                                                                    { class: 'linklike', title: `Search for ${g.query}` })]);
  return { offer: [], result: [el('p', { class: 'reach', id: 'searchAdds',
    title: 'An event holding two of these words counts in each, so the words can add up to more than the total inside' },
    'Without Whole word: ', r.total ? button(plural(r.total, 'event'), () => run(r.forgiving_query),
                                             { class: 'linklike', title: `Search for ${r.forgiving_query}` }) : '0 events',
    r.inside ? `, ${r.inside.toLocaleString()} of them inside other words: ` : ', none of them inside other words.', ...groups,
    r.more ? ` · and ${plural(r.more, 'more word')}` : '', r.inside ? '. ' : ' ',
    button('Hide', () => { forgiving = null; rerender(); }, { class: 'linklike' }))] };
}

// "Also found by name: 1 rule, 8 events below", a link that scrolls the box under the results into view. The box's own head
// would sit behind the sticky head, so the box keeps a margin as tall as it.
function byNameLink(rules, head) {
  const events = rules.reduce((n, r) => n + r.events.length, 0);
  const text = `Also found by name: ${plural(rules.length, 'rule')}${events ? `, ${plural(events, 'event')}` : ''} below`;
  return button(text, () => {
    const box = $('searchByName');
    if (!box) return;
    box.style.scrollMarginTop = `${head.offsetHeight + 4}px`;
    box.scrollIntoView({ block: 'start' });
  }, { class: 'linklike by-name-link', id: 'searchByNameLink', title: 'Hayabusa rules whose titles hold the search word; their events are listed under the results' });
}

// Hayabusa rules whose titles hold the search's word: free text does not read titles, so they are listed
// under the results, each with the events it hit that the results do not hold.
function byName(res, checked, rerender, q) {
  if (!res.by_name) return [];
  const rules = res.by_name.map((rule) => {
    const { list } = markableList(rule.events, checked, rerender, () => showSearch(q, true), { offsets: false, via: true });
    const outside = rule.count - rule.in_results;
    return el('div', { class: 'by-rule' },
      el('p', {}, 'the Hayabusa rule ', el('b', {}, rule.title), rule.level ? ` (${rule.level})` : '', ' hit ',
        el('b', {}, plural(rule.count, 'event')), '; the field form is ',
        button(rule.query, () => run(rule.query), { class: 'linklike mono', title: 'Search for this' }), '.'),
      ...(rule.in_results ? [el('p', { class: 'muted' }, `${rule.in_results.toLocaleString()} of them ${rule.in_results === 1 ? 'is' : 'are'} in the results above.`)] : []),
      ...(rule.events.length ? [list] : []),
      ...(outside > rule.events.length ? [el('p', { class: 'muted' }, `Listing the first ${rule.events.length} of the other ${outside.toLocaleString()}.`)] : []));
  });
  return [el('div', { class: 'hint-box', id: 'searchByName' },
    el('p', {}, el('b', {}, 'Also found by name:'), ' rule titles are not event text, so free text lists here the rules whose titles hold it.'),
    ...rules)];
}

// A search with no match: what free text covers, what it skips, and the values of those fields that hold the words, each a
// click away. A mark, a role, or a tag is a View value, since search leaves those to the View.
function zeroHint(res) {
  const h = res.hint;
  const list = (words, conj) => `${words.slice(0, -1).join(', ')}, ${conj} ${words[words.length - 1]}`;
  const describe = (e) => ({
    rule: `a Hayabusa rule${e.level ? ` (${e.level})` : ''} that hit ${plural(e.count, 'event')}`,
    tool: `the tool that read ${plural(e.count, 'event')}`, artifact: `an evidence type of ${plural(e.count, 'event')}`,
    run: `a run of ${plural(e.count, 'event')}`, file: `a source file of ${plural(e.count, 'event')}`,
    mark: e.value === 'Unreviewed' ? `${plural(e.count, 'event')} with no mark and no pending suggestion`
      : e.value === 'Suggested' ? `${plural(e.count, 'event')} with a pending suggestion` : `${plural(e.count, 'event')} marked ${e.value}`,
    role: `a host role; its hosts hold ${plural(e.count, 'event')}`, tag: `a tag on ${plural(e.count, 'event')}`,
  })[e.field];
  const row = (e) => el('li', { class: 'demo' },
    el('code', { class: 'mono' }, e.query || describeValue(e.view)), ' ', el('span', { class: 'muted' }, describe(e)), ' ',
    e.query ? button(`Search ${e.query}`, () => run(e.query), { class: 'linklike' })
      : button('Show in the View', () => addViewValue(e.view), { class: 'linklike', title: 'Show these events on the timeline through the View filter' }));
  const forms = [...(h.word ? [[`"${h.word}"`, ' for the whole word in free text; '], [`${h.word}*`, ' for a prefix; ']] : []),
                 [`-host:${S.meta?.hosts?.[0]?.host || 'NAME'}`, ' to leave a host out']];
  return [
    el('div', { class: 'list-head' }, el('strong', {}, 'No event matches ', el('i', {}, res.query), h.text_only ? ' as free text.' : '.')),
    el('p', { class: 'reach' }, `Free text searches the ${list(h.covers, 'and')}. It does not search the ${list(h.skips, 'or')}.` +
                                (h.found.length ? ' These hold it:' : '')),
    ...(h.found.length ? [el('div', { class: 'hint-box', id: 'searchHint' }, el('ul', {}, ...h.found.map(row)),
      el('p', { class: 'muted' }, 'A field value compares as a whole, in any letter case, with * for any text. The ? button lists every field.'))] : []),
    el('p', { class: 'muted' }, 'Other forms: ', ...forms.flatMap(([code, what]) => [el('code', { class: 'mono' }, code), what]), '.'),
  ];
}
