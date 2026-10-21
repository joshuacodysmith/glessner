"""The design language's tokens and rules, held against app.css, draw.js, and contrast_record.md's table, whose rows
give each token pair's light and dark ratios, the ratio it needs, and what it is used for. No browser: the CSS is
parsed with the standard library, tokens are resolved the way the page resolves them (var() and color-mix in sRGB),
and each pair's contrast is computed with the WCAG 2.x formula."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
CSS = ROOT / "src" / "glessner" / "static" / "app.css"
DRAW = ROOT / "src" / "glessner" / "static" / "js" / "draw.js"
CONTRAST = ROOT / "contrast_record.md"

# The color tokens of the design language, in both schemes
COLOR_TOKENS = {
    "--bg", "--panel", "--panel-2", "--fg", "--muted", "--line", "--line-strong", "--accent", "--focus",
    "--unreviewed", "--authorized", "--suspicious", "--malicious",
    "--unreviewed-text", "--authorized-text", "--suspicious-text", "--malicious-text",
    "--fill-authorized", "--fill-suspicious", "--fill-malicious", "--on-fill", "--on-amber",
    "--band-timeline", "--band-timeline-edge", "--band-details", "--band-details-edge", "--mark-bg",
    "--related", "--d1", "--d5", "--hit", "--link", "--select", "--row-alt"}
COMPOSITE_TOKENS = {"--state-bg", "--decision-bg", "--decision-bg-malicious", "--decision-bg-authorized", "--pressed-bg"}
MARK_TOKENS = ("unreviewed", "authorized", "suspicious", "malicious")


# ---------- reading the CSS ----------

def strip_comments(text):
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def split_declarations(body):
    """The `name: value` pairs of a rule's body, split on the semicolons outside parentheses and quotes."""
    out, depth, quote, start = [], 0, "", 0
    for i, ch in enumerate(body + ";"):
        if quote:
            quote = "" if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == ";" and depth == 0:
            piece = body[start:i].strip()
            start = i + 1
            if ":" in piece:
                name, value = piece.split(":", 1)
                out.append((name.strip(), value.strip()))
    return out


def parse_rules(text, scope=""):
    """Every rule of a stylesheet as (scope, selector, declarations), with the rules inside an @media block given that
    block's condition as their scope. Other at-rules (keyframes) are skipped."""
    rules, i, n = [], 0, len(text)
    while i < n:
        j = text.find("{", i)
        if j < 0:
            break
        prelude, depth, k = text[i:j].strip(), 1, j + 1
        while k < n and depth:
            depth += {"{": 1, "}": -1}.get(text[k], 0)
            k += 1
        body = text[j + 1:k - 1]
        if prelude.startswith("@media"):
            rules += parse_rules(body, prelude)
        elif not prelude.startswith("@"):
            rules.append((scope, prelude, split_declarations(body)))
        i = k
    return rules


def css_rules():
    return parse_rules(strip_comments(CSS.read_text(encoding="utf-8")))


def token_blocks():
    """The light and the dark :root blocks as {token: value}."""
    light, dark = {}, {}
    for scope, selector, declarations in css_rules():
        if selector == ":root":
            (dark if "dark" in scope else light).update({n: v for n, v in declarations if n.startswith("--")})
    return light, dark


def scheme_tokens(scheme):
    """Every token in effect in a scheme: the light block, with the dark block laid over it for dark."""
    light, dark = token_blocks()
    return {**light, **dark} if scheme == "dark" else dict(light)


# ---------- colors and contrast ----------

def resolve(value, tokens):
    """A color value as (r, g, b) on 0 to 255: #rrggbb, var(--token), or color-mix(in srgb, A p%, B), each channel
    rounded as the page's 8-bit color is."""
    value = value.strip()
    if value.startswith("#"):
        return tuple(int(value[i:i + 2], 16) for i in (1, 3, 5))
    if m := re.fullmatch(r"var\((--[\w-]+)\)", value):
        if m.group(1) not in tokens:
            raise KeyError(f"{m.group(1)} is not defined")
        return resolve(tokens[m.group(1)], tokens)
    if m := re.fullmatch(r"color-mix\(in srgb,\s*(.+?)\s+(\d+(?:\.\d+)?)%\s*,\s*(.+)\)", value):
        first, share, second = resolve(m.group(1), tokens), float(m.group(2)) / 100, resolve(m.group(3), tokens)
        return tuple(round(a * share + b * (1 - share)) for a, b in zip(first, second, strict=True))
    raise ValueError(f"cannot resolve {value!r}")


def luminance(rgb):
    def lin(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (lin(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def pair_ratio(pair, scheme):
    """The contrast of a table pair written "`--a` on `--b`", in a scheme."""
    m = re.fullmatch(r"`(--[\w-]+)` on `(--[\w-]+)`", pair)
    assert m, f"pair {pair!r} is not written as `--a` on `--b`"
    tokens = scheme_tokens(scheme)
    return contrast(resolve(f"var({m.group(1)})", tokens), resolve(f"var({m.group(2)})", tokens))


def contrast_table():
    """The rows of the contrast table as (pair, light, dark, needs, used for), the ratios as numbers."""
    rows, in_table = [], False
    for line in CONTRAST.read_text(encoding="utf-8").splitlines():
        if line.startswith("| Pair |"):
            in_table = True
            assert [c.strip() for c in line.strip("|").split("|")] == ["Pair", "Light", "Dark", "Needs", "Used for"]
            continue
        if in_table and line.startswith("|---"):
            continue
        if in_table and line.startswith("|"):
            pair, light, dark, needs, used = (c.strip() for c in line.strip("|").split("|"))
            rows.append((pair, float(light.removesuffix(":1")), float(dark.removesuffix(":1")),
                         None if needs == "none" else float(needs), used))
        elif in_table:
            break
    return rows


# ---------- the tests ----------

def test_every_color_token_is_defined_in_both_schemes():
    """The light and the dark block define the same color tokens, the design language's names among them, and every
    var() the stylesheet reads is defined. The surfaces mixed from tokens are defined once and resolve in each scheme."""
    light, dark = token_blocks()
    light_colors = {n for n, v in light.items() if re.fullmatch(r"#[0-9a-f]{6}", v)}
    dark_colors = {n for n, v in dark.items() if re.fullmatch(r"#[0-9a-f]{6}", v)}
    assert light_colors >= COLOR_TOKENS, sorted(COLOR_TOKENS - light_colors)
    assert light_colors == dark_colors, sorted(light_colors ^ dark_colors)
    assert {n for n, v in light.items() if v.startswith("color-mix")} >= COMPOSITE_TOKENS
    for scheme in ("light", "dark"):
        tokens = scheme_tokens(scheme)
        for name in COMPOSITE_TOKENS:
            resolve(f"var({name})", tokens)
    defined = set(light)
    for _, selector, declarations in css_rules():
        for name, value in declarations:
            for used in re.findall(r"var\((--[\w-]+)", value):
                # --label-w, --head-h, and --list-head-h are sizes the page's scripts set, with a fallback where they are
                # read; --cols and --off are a list's column widths, set on the list by its own rules, not colors or
                # theme tokens
                known = used in defined or used in ("--label-w", "--head-h", "--list-head-h", "--cols", "--off")
                assert known, f"{selector} {name} reads {used}, which no block defines"


def test_no_color_literal_outside_the_token_blocks():
    """A color is written once, in a token block. Elsewhere only a token, transparent, or a box-shadow's rgba."""
    for _, selector, declarations in css_rules():
        if selector == ":root":
            continue
        for name, value in declarations:
            assert not re.search(r"#[0-9a-fA-F]{3,8}\b", value), f"{selector} {name}: {value}"
            if name == "box-shadow":
                value = value.replace("rgba(", "(")
            assert not re.search(r"\b(?:rgb|rgba|hsl|hsla|hwb|lab|lch|oklch|oklab)\(", value), f"{selector} {name}: {value}"


def test_the_contrast_record_holds():
    """The contrast table is the record. Each row's ratios, computed from the tokens in app.css in both schemes with
    the WCAG formula, meet the row's Needs and equal the recorded ratio within 0.01."""
    rows = contrast_table()
    assert len(rows) >= 70, len(rows)
    for pair, light, dark, needs, _ in rows:
        for scheme, documented in (("light", light), ("dark", dark)):
            ratio = pair_ratio(pair, scheme)
            assert abs(ratio - documented) <= 0.01, f"{pair} {scheme}: computed {ratio:.2f}, documented {documented}"
            if needs is not None:
                assert ratio >= needs, f"{pair} {scheme}: {ratio:.2f} needs {needs}"


def test_text_never_reads_a_mark_token():
    """The mark tokens are for ticks, bars, and swatches. A color, border, outline, or underline color that a person
    reads takes the -text token, so the broad flag is readable and amber keeps one meaning."""
    bare = re.compile(rf"var\(--(?:{'|'.join(MARK_TOKENS)})\)")
    for _, selector, declarations in css_rules():
        for name, value in declarations:
            if name == "color" or name.startswith(("border", "outline")) or name == "text-decoration-color":
                assert not bare.search(value), f"{selector} {name}: {value}"


def test_group_lanes_are_the_page_background():
    """--group is retired: group lanes take --bg, on the canvas and in the labels, and the canvas reads each mark's tick
    token, never its -text token."""
    text = CSS.read_text(encoding="utf-8")
    assert "--group" not in text and "--group" not in DRAW.read_text(encoding="utf-8")
    draw = DRAW.read_text(encoding="utf-8")
    assert "group: cssVar('--bg')" in draw
    assert "cssVar(`--${m.toLowerCase()}`)" in draw
    assert "-text" not in "".join(re.findall(r"cssVar\([^)]*\)", draw))
    labels = [d for _, s, ds in css_rules() if s == "#labels .row.group" for d in ds]
    assert ("background", "var(--bg)") in labels


def test_one_focus_ring():
    """No rule removes the outline, and one :focus-visible rule draws the ring in --focus."""
    ring = []
    for _, selector, declarations in css_rules():
        for name, value in declarations:
            if name.startswith("outline"):
                assert value not in ("none", "0"), f"{selector} {name}: {value}"
        if selector == ":focus-visible":
            ring = declarations
    assert ("outline", "2px solid var(--focus)") in ring and ("outline-offset", "1px") in ring


def test_scheme_and_placeholder_rules():
    """Native controls follow the scheme, and a placeholder is --muted at full opacity."""
    rules = css_rules()
    root = [d for _, s, ds in rules if s == ":root" for d in ds]
    assert ("color-scheme", "light dark") in root
    placeholder = [d for _, s, ds in rules if s == "::placeholder" for d in ds]
    assert ("color", "var(--muted)") in placeholder and ("opacity", "1") in placeholder


def test_links_use_accent():
    """One global link-like button in --accent replaces the scoped copies, and no text takes --d5, which stays for
    density, the match strip, the spinner, and progress."""
    rules = css_rules()
    glob = [ds for _, s, ds in rules if s == "button.linklike"]
    assert len(glob) == 1 and ("color", "var(--accent)") in glob[0]
    for _, selector, declarations in rules:
        if "linklike" in selector and selector not in ("button.linklike", "button.linklike:hover"):
            for name, _ in declarations:
                assert name not in ("color", "border", "background", "padding"), f"{selector} restyles a link: {name}"
        for name, value in declarations:
            assert not (name == "color" and value == "var(--d5)"), f"{selector} colors text with --d5"
