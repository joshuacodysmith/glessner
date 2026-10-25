import { $, api, HINTS, plural, showControls } from './core.js';

// ---------- counts on the case buttons ----------

export async function refreshCounts() {
  let c;
  try { c = await api('/api/counts'); } catch (_) { return; }
  const show = (id, n, text) => { const badge = $(id); badge.hidden = !n; badge.textContent = text; };
  show('flaggedCount', c.flagged, c.flagged.toLocaleString());
  show('pendingCount', c.pending, `${c.pending.toLocaleString()} pending`);
  show('hostsCount', c.hosts_review, `${c.hosts_review} to review`);
  show('ruleErrorCount', c.rule_errors, plural(c.rule_errors, 'error'));
  $('investigateButton').title = `${HINTS.investigateButton} ${plural(c.flagged, 'event')} marked Malicious or Suspicious; ` +
                                 `${plural(c.pending, 'event')} with a suggestion waiting for a decision.`;
  // A host whose event logs record several computers is named, since its notice shows only in the Hosts panel and
  // the host often needs review for its role already.
  const mixed = c.hosts_mixed || [];
  const hostsTitle = c.hosts_review
    ? `${c.hosts_review === 1 ? '1 host needs' : `${c.hosts_review} hosts need`} review: a role not confirmed, ` +
      'a name or IP another host also claims, logons from one of its IPs that name another machine, ' +
      'a clock that looks off from the capture, or event logs recorded by several computers' +
      (mixed.length ? `. ${mixed.map((name) => showControls(name)).join(', ')} can be split by recorded computer: open Hosts` : '')
    : 'Every host role is confirmed, and no name or IP is claimed twice';
  $('hostsButton').title = `${HINTS.hostsButton} ${hostsTitle}.`;
  $('rulesButton').title = c.rule_errors ? `${HINTS.rulesButton} ${plural(c.rule_errors, 'rule')} failed to compile or run.`
    : HINTS.rulesButton;
  // The Case menu's button carries its items' counts, so what needs attention shows while the menu is closed
  const flags = [c.hosts_review ? `${c.hosts_review} to review` : '', c.rule_errors ? plural(c.rule_errors, 'error') : ''].filter(Boolean);
  show('caseMenuCount', flags.length, flags.join(', '));
  $('caseMenuButton').title = flags.length ? `${HINTS.caseMenuButton} Hosts to review: ${c.hosts_review}; rule errors: ${c.rule_errors}.`
    : HINTS.caseMenuButton;
}
