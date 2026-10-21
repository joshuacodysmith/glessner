import { $, el, fmtUs, post, S, setStatus } from './core.js';
import { draw } from './draw.js';
import { button } from './event_page.js';
import { hostInfo } from './hosts.js';
import { closeQuickMenu, menuItem, placeMenu } from './quick_menu.js';

// ---------- time-zone axes ----------
// UTC stays the main axis. The analyst adds zone axes under it, from the hosts' own zones (each SYSTEM hive's
// TimeZoneInformation, mapped to an IANA zone on the server) or any IANA zone. They are saved with the case.

export const COMMON_ZONES = ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'Europe/London',
                      'Europe/Berlin', 'Asia/Tokyo', 'Australia/Sydney'];
export const MAX_ZONE_AXES = 6;

export function fmtOffset(min) {
  const sign = min < 0 ? '-' : '+', a = Math.abs(min), h = Math.floor(a / 60), m = a % 60;
  return `${sign}${h}${m ? `:${String(m).padStart(2, '0')}` : ''}`;
}

// A clock turns UTC milliseconds into local date and time parts, the zone's abbreviation, and its UTC offset.
export function ianaClock(zone) {
  const f = new Intl.DateTimeFormat('en-US', { timeZone: zone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit',
                                               hour: '2-digit', minute: '2-digit', second: '2-digit', timeZoneName: 'short' });
  return {
    parts(ms) {
      const p = Object.fromEntries(f.formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
      const h = String(Number(p.hour) % 24).padStart(2, '0');
      const local = Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day), Number(h), Number(p.minute), Number(p.second));
      return { y: p.year, mo: p.month, d: p.day, h, mi: p.minute, s: p.second, abbr: p.timeZoneName,
               offset: Math.round((local - Math.floor(ms / 1000) * 1000) / 60000) };
    },
  };
}

// A fixed offset, for a host whose zone has no IANA match or had daylight saving turned off.
export function fixedClock(offset) {
  return {
    parts(ms) {
      const iso = new Date(ms + offset * 60000).toISOString();
      return { y: iso.slice(0, 4), mo: iso.slice(5, 7), d: iso.slice(8, 10), h: iso.slice(11, 13), mi: iso.slice(14, 16),
               s: iso.slice(17, 19), abbr: `UTC${fmtOffset(offset)}`, offset };
    },
  };
}

export const zoneKey = (tz) => `${tz.windows}|${tz.iana}|${tz.bias_minutes}`;

// The clock and label for one axis: { host } for a host's own zone, or { zone } for an IANA zone.
export function zoneClock(spec) {
  if (spec.host) {
    const tz = (hostInfo(spec.host) || {}).timezone;
    if (!tz || (!tz.iana && tz.bias_minutes == null)) return null;
    const sharing = S.meta.hosts.filter((h) => h.timezone && h.timezone.windows !== undefined && zoneKey(h.timezone) === zoneKey(tz)).map((h) => h.host);
    const who = sharing.length > 2 ? `${sharing.slice(0, 2).join(', ')} +${sharing.length - 2}` : sharing.join(', ');
    const name = tz.windows || `UTC${fmtOffset(-tz.bias_minutes)}`;
    if (tz.iana) {
      return { clock: ianaClock(tz.iana), label: `${who}: ${name}`,
               title: `${name} (${tz.iana}), from the ${tz.source}. Hosts in this zone: ${sharing.join(', ')}.` };
    }
    return { clock: fixedClock(-tz.bias_minutes), label: `${who}: ${name}, fixed offset`,
             title: `${name}: the registry's fixed Bias, without daylight saving, because ` +
                    `${tz.dst_disabled ? 'the host had daylight saving turned off' : 'no IANA zone matches'}. From the ${tz.source}.` };
  }
  try { return { clock: ianaClock(spec.zone), label: spec.zone, title: spec.zone }; } catch (_) { return null; }
}

export function fmtLocal(clock, us) {
  const p = clock.parts(Math.floor(us / 1000));
  return `${p.y}-${p.mo}-${p.d} ${p.h}:${p.mi}:${p.s}${fmtUs(us).slice(19)} ${p.abbr}`;
}

// The event's time on its host's own clock, when the host's zone is known, for the Event page's time hover: the time as
// recorded, which a clock offset doesn't move, not the adjusted time, which no clock read.
export function hostLocalText(ev) {
  const z = ev.ts_us == null ? null : zoneClock({ host: ev.host });
  return z ? `Local time on ${ev.host}: ${fmtLocal(z.clock, ev.ts_us)}\n${z.title}` : '';
}

// Build one row per zone axis under the UTC axis: a label with the zone's offset in the window, and a canvas.
export function renderZoneAxes() {
  const row = $('axisRow');
  for (const old of row.querySelectorAll('.zone-line')) old.remove();
  S.zoneAxes = [];
  S.zones.forEach((spec, i) => {
    const z = zoneClock(spec);
    if (!z) return;
    const offsetEl = el('span', { class: 'zoffset' });
    const label = el('div', { class: 'zone-label zone-line', title: z.title }, el('span', { class: 'zname' }, z.label), offsetEl,
                     button('×', () => saveZones(S.zones.filter((_, k) => k !== i)), { 'aria-label': `Remove the ${z.label} axis` }));
    const canvas = el('canvas', { class: 'zone-axis zone-line' });
    row.append(label, canvas);
    S.zoneAxes.push({ spec, clock: z.clock, canvas, offsetEl });
  });
  if (S.data) draw();
}

export async function saveZones(zones) {
  try {
    const res = await post('/api/setting', { name: 'time_zones', value: zones });
    S.zones = res.value;
    S.meta.time_zones = res.value;
  } catch (err) { setStatus(`Time zone change failed: ${err.message}`); return; }
  renderZoneAxes();
}

export function openZoneMenu(x, y) {
  closeQuickMenu();
  const used = new Set(S.zones.map((z) => JSON.stringify(z)));
  const full = S.zones.length >= MAX_ZONE_AXES;
  const add = (spec) => saveZones([...S.zones, spec]);
  const items = [];
  const groups = new Map();
  for (const h of S.meta.hosts) {
    const tz = h.timezone;
    if (!tz || (!tz.iana && tz.bias_minutes == null)) continue;
    if (!groups.has(zoneKey(tz))) groups.set(zoneKey(tz), h.host);
  }
  items.push(el('div', { class: 'menu-group' }, groups.size ? "Hosts' own zones, from their SYSTEM hives" : 'No host recorded a time zone'));
  for (const host of groups.values()) {
    const spec = { host };
    // Any host of a zone stands for all of them, so a zone already shown through another host counts as used.
    const shown = S.zones.some((z) => z.host && zoneKey((hostInfo(z.host) || {}).timezone || {}) === zoneKey(hostInfo(host).timezone));
    items.push(menuItem(zoneClock(spec).label, () => add(spec), { disabled: full || shown }));
  }
  const local = Intl.DateTimeFormat().resolvedOptions().timeZone;
  items.push(el('div', { class: 'menu-group' }, 'Other zones'));
  for (const zone of [local, ...COMMON_ZONES.filter((z) => z !== local)]) {
    items.push(menuItem(zone === local ? `${zone} (this computer)` : zone, () => add({ zone }),
                        { disabled: full || used.has(JSON.stringify({ zone })) }));
  }
  const input = el('input', { type: 'text', placeholder: 'An IANA name, such as Asia/Kolkata', size: '26' });
  const msg = el('div', { class: 'muted' });
  const addTyped = () => {
    const typed = input.value.trim();
    let zone;
    try { zone = new Intl.DateTimeFormat('en-US', { timeZone: typed }).resolvedOptions().timeZone; }
    catch (_) { msg.textContent = `This browser doesn't know a zone named ${typed || '(empty)'}.`; return; }
    // Keep the analyst's name, such as Asia/Kolkata, rather than the browser's older alias (Asia/Calcutta). Typed
    // all in lower case, it gets capitals at each part (asia/kolkata, america/new_york), if the browser accepts that.
    const named = /[A-Z]/.test(typed) ? typed : typed.replace(/(^|[/_])([a-z])/g, (m, sep, ch) => sep + ch.toUpperCase());
    try { new Intl.DateTimeFormat('en-US', { timeZone: named }); zone = named; } catch (_) { /* keep the browser's name */ }
    closeQuickMenu();
    add({ zone });
  };
  input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') addTyped(); });
  const menu = $('quickMenu');
  menu.setAttribute('aria-label', 'Add a time-zone axis');
  menu.replaceChildren(
    el('div', { class: 'menu-head' }, el('div', {}, 'Add a time-zone axis'),
       el('div', { class: 'muted' }, full ? `At most ${MAX_ZONE_AXES} zone axes; remove one first.`
                                          : 'Its ticks line up with the UTC axis above. Saved with the case.')),
    ...items, el('hr'),
    el('div', { class: 'menu-foot' }, input, ' ', button('Add', addTyped, full ? { disabled: '' } : {})), msg);
  placeMenu(x, y);
  const first = menu.querySelector('button:not([disabled])');
  if (first) first.focus();
}
