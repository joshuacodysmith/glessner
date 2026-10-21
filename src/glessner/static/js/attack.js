import { api, el } from './core.js';

// ---------- Enterprise ATT&CK's techniques, for a finding's ATT&CK field and the tag picker ----------
// A box that lists Enterprise ATT&CK's techniques as the analyst types an ID or words of a name. Only a listed technique can
// be picked: the arrow keys move through the list, Enter or a click picks, and Escape closes it. A revoked ID typed names its
// replacement, in the server's words. The list comes once from /api/attack (attack.py), and the server refuses an unlisted
// ID too. A finding's field shows the picked techniques as chips, each with × to remove it. An ID a finding held before the
// list came, which isn't on it, shows as a flagged chip that can be removed but not added back, and an edit of the
// techniques must remove it first. The flag is the server's, such as "revoked; now T1059.001".
// The tag picker's box tags the events with the one technique picked.

const SHOWN = 50;   // matches the list shows; past that, the hint asks for more of the ID or name
const HINT = 'Type an ID or a name, then pick from the list';
let list = null;    // the promise of /api/attack's answer, read once per page
let made = 0;       // numbers each box, for its list's element IDs

export function attackList() {
  if (!list) list = api('/api/attack').catch((err) => { list = null; throw err; });
  return list;
}

// The box and its list, with the hint line under it. `taken()` gives the IDs to leave out of the list, and `already(id)` the
// hint for one of them typed; `onPick(id)` takes a picked one, and `onLoad()` runs when the list has come. Returns the box's
// `node`, its `input` and `hint`, the technique `names`, and `version()`.
function attackBox({ label, placeholder, taken, already, onPick, onLoad = () => {} }) {
  const n = ++made, listId = `attackList${n}`;
  const names = new Map();
  let rows = [], tactics = new Map(), revoked = {}, version = '', shown = [], active = -1;
  const input = el('input', { type: 'text', role: 'combobox', 'aria-label': label, 'aria-autocomplete': 'list',
                              'aria-expanded': 'false', 'aria-controls': listId, autocomplete: 'off', spellcheck: 'false',
                              placeholder });
  const box = el('div', { class: 'attack-list', id: listId, role: 'listbox', 'aria-label': 'ATT&CK techniques' });
  const more = el('div', { class: 'attack-more muted', hidden: '' });   // past SHOWN matches, at the list's foot
  const pop = el('div', { class: 'attack-pop', hidden: '' }, box, more);
  const hint = el('div', { class: 'attack-hint muted', 'aria-live': 'polite' }, `${HINT}.`);
  const say = (text) => { hint.textContent = text; };
  const resting = () => say(version ? `${HINT} (Enterprise ATT&CK v${version}).` : `${HINT}.`);

  // An ID, with or without its T, matches from its start; words match a name in any order. ID matches come first.
  const matches = (text) => {
    const q = text.trim().toLowerCase();
    if (!q) return [];
    const out = taken();
    const free = rows.filter(([id]) => !out.includes(id));
    const prefix = /^t?\d/.test(q) ? (q[0] === 't' ? q : `t${q}`) : null;
    const byId = prefix ? free.filter(([id]) => id.toLowerCase().startsWith(prefix)) : [];
    const words = q.split(/\s+/);
    const byName = free.filter(([id, name]) => !byId.some((r) => r[0] === id) && words.every((w) => name.toLowerCase().includes(w)));
    return [...byId, ...byName];
  };
  const close = () => {
    pop.hidden = true;
    input.setAttribute('aria-expanded', 'false');
    input.removeAttribute('aria-activedescendant');
    active = -1;
  };
  const highlight = (i) => {
    active = i;
    [...box.children].forEach((o, k) => { o.setAttribute('aria-selected', String(k === i)); o.classList.toggle('active', k === i); });
    if (i < 0) { input.removeAttribute('aria-activedescendant'); return; }
    input.setAttribute('aria-activedescendant', `${listId}-${i}`);
    box.children[i].scrollIntoView({ block: 'nearest' });
  };
  const pick = (id) => {
    input.value = '';
    close();
    resting();
    onPick(id);
  };
  // The words of what matched nothing: an ID left out as taken says so, and a revoked ID names its replacement, as the
  // server's refusal does (attack.tag_refusal)
  const unmatched = (typed) => {
    const id = typed.toUpperCase().replace(/^(?=\d)/, 'T');
    if (taken().includes(id)) return already(id);
    return revoked[id] ? `${id} is revoked in ATT&CK v${version}; it's now ${revoked[id]}.`
      : `No Enterprise ATT&CK v${version} technique matches "${typed}".`;
  };
  const draw = () => {
    if (!rows.length) return;   // the list hasn't come yet: it draws when it does
    const found = matches(input.value);
    shown = found.slice(0, SHOWN);
    box.replaceChildren(...shown.map(([id, name, of], i) => el('div', {
      role: 'option', id: `${listId}-${i}`, class: 'attack-opt', 'aria-selected': 'false', 'data-technique': id,
      onclick: () => pick(id) }, el('span', { class: 'tid' }, id), ` ${name}`,
      el('span', { class: 'muted' }, ` · ${of.map((t) => tactics.get(t) || t).join(', ')}`))));
    if (!input.value.trim()) { close(); resting(); return; }
    if (!shown.length) {
      close();
      say(unmatched(input.value.trim()));
      return;
    }
    pop.hidden = false;
    input.setAttribute('aria-expanded', 'true');
    // Below the box, unless the window ends first, as it can for the tag picker's menu near the window's foot
    pop.classList.remove('up');
    if (pop.getBoundingClientRect().bottom > window.innerHeight) pop.classList.add('up');
    highlight(0);
    // The open list covers the hint, so a long list says so at its foot as well; the hint carries it to a screen reader
    const over = found.length > SHOWN ? `Showing ${SHOWN} of ${found.length}. Type more of the ID or name to narrow the list.` : '';
    more.textContent = over;
    more.hidden = !over;
    if (over) say(over); else resting();
  };

  input.addEventListener('input', draw);
  input.addEventListener('blur', close);
  pop.addEventListener('mousedown', (ev) => ev.preventDefault());   // the focus stays in the box, so a click picks before a blur closes
  input.addEventListener('keydown', (ev) => {
    const open = !pop.hidden;
    if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
      if (!open && !input.value.trim()) return;   // an empty box leaves the keys to what holds it: the tag picker's menu moves on
      ev.preventDefault();
      ev.stopPropagation();
      if (!open) { draw(); return; }
      highlight(ev.key === 'ArrowDown' ? Math.min(active + 1, shown.length - 1) : Math.max(active - 1, 0));
    } else if (ev.key === 'Enter') {
      ev.preventDefault();
      if (open && active >= 0) pick(shown[active][0]);
    } else if (ev.key === 'Escape' && open) {
      ev.preventDefault();
      ev.stopPropagation();
      close();
    } else if ((ev.key === 'Home' || ev.key === 'End') && input.value) {
      ev.stopPropagation();   // they move the caret in the text, not the tag picker's menu to its first or last item
    }
  });

  attackList().then((res) => {
    rows = res.techniques;
    for (const [id, name] of rows) names.set(id, name);
    tactics = new Map(res.tactics);
    revoked = res.revoked || {};
    version = res.version;
    hint.title = res.copyright;
    onLoad();
    // Text typed before the list came draws it, unless the analyst has moved on: no blur would close it then
    if (input.value.trim() && document.activeElement === input) draw(); else resting();
  }).catch((err) => say(`Could not load the ATT&CK list: ${err.message}`));

  return { node: el('div', { class: 'attack-input' }, input, pop), input, hint, names, version: () => version };
}

// The field for a finding's `ids`, with the server's `flags` for those not listed. Returns its node, `ids()` for the picked
// IDs in order, and `problem(original)`: why Save can't take the field, or '' (text typed and not picked, or a flagged ID
// kept while the techniques changed from `original`).
export function attackField(ids, flags = {}) {
  const picked = [...ids];
  const chips = el('div', { class: 'attack-chips' });
  const b = attackBox({
    label: 'ATT&CK techniques', placeholder: 'ATT&CK technique (optional)', taken: () => picked,
    already: (id) => `${id} is picked already.`,
    onPick: (id) => { picked.push(id); drawChips(); b.input.focus(); }, onLoad: () => drawChips() });
  const node = el('div', { class: 'attack-field' }, b.node, chips, b.hint);

  function drawChips() {
    chips.replaceChildren(...picked.map((id) => {
      const off = flags[id] || '';
      return el('span', { class: `attack-chip${off ? ' off-list' : ''}`, 'data-technique': id },
        el('span', { class: 'label' }, el('span', { class: 'tid' }, id), ` ${off || b.names.get(id) || ''}`),
        el('button', { type: 'button', 'aria-label': `Remove ${id}`, onclick: () => {
          picked.splice(picked.indexOf(id), 1);
          drawChips();
          b.input.focus();
        } }, '×'));
    }));
  }
  drawChips();

  const problem = (original) => {
    const typed = b.input.value.trim();
    if (typed) return `"${typed}" isn't picked. Pick a technique from the list, or clear the ATT&CK box.`;
    const off = JSON.stringify(picked) === JSON.stringify(original) ? [] : picked.filter((id) => flags[id]);
    if (!off.length) return '';
    const one = off.length === 1;
    const version = b.version();
    return `${off.join(', ')} ${one ? "isn't" : "aren't"} in ATT&CK${version ? ` v${version}` : ''}. ` +
      `Remove ${one ? 'it' : 'them'} to save the ATT&CK field.`;
  };
  return { node, ids: () => [...picked], problem };
}

// The tag picker's technique box: the one technique picked goes to `onPick(id)`, which tags the events. `taken`
// holds the techniques the one event being tagged already has, which the list leaves out.
export function attackPicker(onPick, taken = []) {
  const b = attackBox({ label: 'ATT&CK technique', placeholder: 'ID or name, such as T1021.001', taken: () => taken,
                        already: (id) => `${id} is on this event already.`, onPick });
  return { node: el('div', { class: 'attack-field' }, b.node, b.hint), input: b.input };
}
