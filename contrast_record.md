# Contrast record

Glessner's colors are CSS custom properties, or tokens, in `src/glessner/static/app.css`, each defined for the light
and the dark scheme. This table records the contrast of each pair of tokens the page draws text, marks, or a control's
parts with, in both schemes.

`tests/test_design_tokens.py` parses this table, resolves each token from `app.css` in both schemes, computes each
ratio with the [WCAG 2](https://www.w3.org/TR/WCAG22/) contrast ratio formula (sRGB channels linearized, the lighter
luminance plus 0.05 over the darker plus 0.05), and fails when a ratio is under its Needs or differs from the recorded
ratio by more than 0.01.

- **Pair:** token names only, the text or part first and its background second.
- **Needs:** 4.5 for text under 18 px; 3.0 for bold text of 14 px and up, large text, and the parts of a control; none
  for a pair that carries no threshold.

Ticks of different marks on the timeline differ by hue, and lightness alone doesn't tell them apart in either scheme
(1.0 to 1.8:1). Each mark's badge adds a letter. A new color pair goes into this table in the change that adds it.

| Pair | Light | Dark | Needs | Used for |
|---|---|---|---|---|
| `--fg` on `--panel` | 17.17:1 | 13.65:1 | 4.5 | body text on a panel |
| `--fg` on `--bg` | 15.44:1 | 15.33:1 | 4.5 | body text on the page background, group lane labels |
| `--fg` on `--panel-2` | 15.85:1 | 12.66:1 | 4.5 | body text on the tinted work column |
| `--fg` on `--band-timeline` | 13.40:1 | 13.09:1 | 4.5 | text in the Timeline band |
| `--fg` on `--band-details` | 15.24:1 | 11.99:1 | 4.5 | text in the Details band |
| `--fg` on `--state-bg` | 14.84:1 | 13.37:1 | 4.5 | the state line's counts |
| `--fg` on `--decision-bg` | 14.96:1 | 11.15:1 | 4.5 | the decision box's text |
| `--fg` on `--decision-bg-malicious` | 14.56:1 | 11.73:1 | 4.5 | the decision box's text for a Malicious suggestion |
| `--fg` on `--decision-bg-authorized` | 15.00:1 | 11.44:1 | 4.5 | the decision box's text for an Authorized suggestion |
| `--fg` on `--pressed-bg` | 14.34:1 | 10.79:1 | 4.5 | the label of a pressed toggle |
| `--fg` on `--mark-bg` | 13.94:1 | 5.69:1 | 4.5 | a highlighted search term |
| `--panel` on `--fg` | 17.17:1 | 13.65:1 | 4.5 | the lead button's label on its fill |
| `--muted` on `--panel` | 6.61:1 | 6.49:1 | 4.5 | secondary text, labels, reasons, placeholders |
| `--muted` on `--bg` | 5.94:1 | 7.29:1 | 4.5 | lane counts, the rank disc, the path |
| `--muted` on `--panel-2` | 6.10:1 | 6.02:1 | 4.5 | reasons on the tinted work column |
| `--muted` on `--band-timeline` | 5.16:1 | 6.23:1 | 4.5 | labels in the Timeline band |
| `--muted` on `--band-details` | 5.87:1 | 5.71:1 | 4.5 | the Details band's name |
| `--muted` on `--state-bg` | 5.71:1 | 6.36:1 | 4.5 | the state line's labels |
| `--muted` on `--pressed-bg` | 5.52:1 | 5.14:1 | 4.5 | the tactics of the highlighted option in the ATT&CK field's list |
| `--accent` on `--panel` | 6.66:1 | 7.70:1 | 4.5 | links and link-like buttons |
| `--accent` on `--panel-2` | 6.14:1 | 7.15:1 | 4.5 | links and the fold toggles on the work column |
| `--accent` on `--band-timeline` | 5.20:1 | 7.39:1 | 4.5 | links in the Timeline band |
| `--accent` on `--band-details` | 5.91:1 | 6.77:1 | 4.5 | the trail's steps, dimmed steps included |
| `--accent` on `--state-bg` | 5.75:1 | 7.55:1 | 4.5 | the state line's Show links |
| `--accent` on `--bg` | 5.99:1 | 8.65:1 | 4.5 | a link on a selected file, and the grip when hovered or focused |
| `--unreviewed-text` on `--panel` | 5.75:1 | 7.36:1 | 4.5 | Unreviewed as text, the U badge's letter and ring |
| `--unreviewed-text` on `--panel-2` | 5.31:1 | 6.83:1 | 4.5 | the U badge on the work column |
| `--authorized-text` on `--panel` | 5.37:1 | 7.46:1 | 4.5 | Authorized as text, "matches intake" |
| `--authorized-text` on `--panel-2` | 4.96:1 | 6.92:1 | 4.5 | "matches intake" on the provenance strip |
| `--suspicious-text` on `--panel` | 5.81:1 | 8.73:1 | 4.5 | Suspicious as text, the broad flag, the review count, the S badge's border |
| `--suspicious-text` on `--panel-2` | 5.37:1 | 8.09:1 | 4.5 | the broad flag on the tinted work column |
| `--suspicious-text` on `--decision-bg` | 5.07:1 | 7.13:1 | 4.5 | the decision box's lead-in, the caution tints |
| `--muted` on `--decision-bg` | 5.76:1 | 5.31:1 | 4.5 | a caveat's sources line |
| `--accent` on `--decision-bg` | 5.80:1 | 6.29:1 | 4.5 | a caveat's source links and its Show less |
| `--suspicious-text` on `--band-timeline` | 4.54:1 | 8.37:1 | 4.5 | the review counts and "partly aligned" in the Timeline band |
| `--suspicious-text` on `--bg` | 5.23:1 | 9.80:1 | 4.5 | the flags on group lane labels |
| `--malicious-text` on `--panel` | 6.57:1 | 6.05:1 | 4.5 | Malicious as text, evidence warnings |
| `--on-fill` on `--fill-authorized` | 5.37:1 | 8.68:1 | 4.5 | the A badge's letter, the Accept chip on hover |
| `--on-amber` on `--fill-suspicious` | 10.25:1 | 10.15:1 | 4.5 | the S badge's letter, the Accept as Suspicious button |
| `--on-fill` on `--fill-malicious` | 6.57:1 | 7.03:1 | 4.5 | the M badge's letter, the flagged count, the Dismiss chip on hover |
| `--line-strong` on `--panel` | 3.85:1 | 3.56:1 | 3.0 | borders of controls on a panel |
| `--line-strong` on `--panel-2` | 3.56:1 | 3.30:1 | 3.0 | borders of controls on the work column |
| `--line-strong` on `--bg` | 3.47:1 | 4.00:1 | 3.0 | the divider grip on the page background |
| `--line-strong` on `--band-timeline` | 3.01:1 | 3.42:1 | 3.0 | the toolbar's button and select borders |
| `--line-strong` on `--band-details` | 3.42:1 | 3.13:1 | 3.0 | the Save trail button's border |
| `--line-strong` on `--state-bg` | 3.33:1 | 3.49:1 | 3.0 | the state line's pill borders |
| `--panel` on `--line-strong` | 3.85:1 | 3.56:1 | 3.0 | the grip's slot against the grip |
| `--focus` on `--panel` | 6.66:1 | 7.70:1 | 3.0 | the focus ring against a panel |
| `--focus` on `--panel-2` | 6.14:1 | 7.15:1 | 3.0 | the focus ring on the work column |
| `--focus` on `--bg` | 5.99:1 | 8.65:1 | 3.0 | the focus ring against the page background |
| `--focus` on `--band-timeline` | 5.20:1 | 7.39:1 | 3.0 | the focus ring in the Timeline band |
| `--focus` on `--band-details` | 5.91:1 | 6.77:1 | 3.0 | the focus ring in the Details band |
| `--focus` on `--state-bg` | 5.75:1 | 7.55:1 | 3.0 | the focus ring on the state line |
| `--fill-authorized` on `--panel` | 5.37:1 | 7.46:1 | 3.0 | the A badge against a list |
| `--fill-malicious` on `--panel` | 6.57:1 | 6.05:1 | 3.0 | the M badge against a list |
| `--fill-authorized` on `--panel-2` | 4.96:1 | 6.92:1 | 3.0 | the A badge on the work column |
| `--fill-malicious` on `--panel-2` | 6.07:1 | 5.61:1 | 3.0 | the M badge on the work column |
| `--band-timeline-edge` on `--bg` | 3.61:1 | 3.56:1 | 3.0 | the Timeline panel's top edge |
| `--band-details-edge` on `--bg` | 3.29:1 | 4.35:1 | 3.0 | the Details panel's top edge |
| `--d5` on `--panel` | 7.96:1 | 7.79:1 | 3.0 | the match strip's bars |
| `--unreviewed` on `--panel` | 4.39:1 | 6.52:1 | 3.0 | an unreviewed tick on its lane |
| `--authorized` on `--panel` | 4.32:1 | 7.32:1 | 3.0 | an authorized tick on its lane |
| `--suspicious` on `--panel` | 3.36:1 | 8.40:1 | 3.0 | a suspicious tick on its lane |
| `--malicious` on `--panel` | 5.90:1 | 4.90:1 | 3.0 | a malicious tick on its lane |
| `--unreviewed` on `--bg` | 3.95:1 | 7.33:1 | 3.0 | an unreviewed tick on a group lane |
| `--authorized` on `--bg` | 3.89:1 | 8.22:1 | 3.0 | an authorized tick on a group lane |
| `--suspicious` on `--bg` | 3.02:1 | 9.43:1 | 3.0 | a suspicious tick on a group lane |
| `--malicious` on `--bg` | 5.31:1 | 5.50:1 | 3.0 | a malicious tick on a group lane |
| `--unreviewed` on `--row-alt` | 4.20:1 | 6.06:1 | 3.0 | an unreviewed tick on an odd lane |
| `--authorized` on `--row-alt` | 4.13:1 | 6.79:1 | 3.0 | an authorized tick on an odd lane |
| `--suspicious` on `--row-alt` | 3.21:1 | 7.80:1 | 3.0 | a suspicious tick on an odd lane |
| `--malicious` on `--row-alt` | 5.65:1 | 4.55:1 | 3.0 | a malicious tick on an odd lane |
| `--muted` on `--mark-bg` | 5.36:1 | 2.71:1 | none | not used: a highlight sets `--fg`, so muted text inside one never has this pair |
| `--accent` on `--mark-bg` | 5.40:1 | 3.21:1 | none | not used: a highlight sets `--fg`, so a link inside one never has this pair |
| `--suspicious` on `--malicious` | 1.76:1 | 1.71:1 | none | tick against tick, S against M |
| `--suspicious` on `--authorized` | 1.29:1 | 1.15:1 | none | tick against tick, S against A |
| `--suspicious` on `--unreviewed` | 1.31:1 | 1.29:1 | none | tick against tick, S against U |
| `--malicious` on `--authorized` | 1.37:1 | 1.49:1 | none | tick against tick, M against A |
| `--malicious` on `--unreviewed` | 1.34:1 | 1.33:1 | none | tick against tick, M against U |
| `--authorized` on `--unreviewed` | 1.02:1 | 1.12:1 | none | tick against tick, A against U |
| `--band-timeline` on `--band-details` | 1.14:1 | 1.09:1 | none | band against band |
| `--band-timeline` on `--panel` | 1.28:1 | 1.04:1 | none | the Timeline band against the panel |
| `--band-details` on `--panel` | 1.13:1 | 1.14:1 | none | the Details band against the panel |
