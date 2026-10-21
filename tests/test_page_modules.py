"""The page's ES modules import what they use. A missing import only fails when its code runs in the browser. ESLint's
no-undef finds a name a module uses without importing it (tests/test_lint.py); this checks what no-undef can't: each
import names something its module exports, no module both declares and imports a name, no exported name is a global
ESLint is told of, which would hide a missing import of it from no-undef, and core.js, which the others load first,
imports nothing. test_lint.py skips ESLint when it isn't installed, so that check needs npm ci --ignore-scripts
(README.md)."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
JS = ROOT / "src" / "glessner" / "static" / "js"
EXPORT = re.compile(r"^export (?:async\s+)?(?:function|const|let)\s+([\w$]+)", re.M)
DECLARED = re.compile(r"^(?:export )?(?:async\s+)?(?:function|const|let)\s+([\w$]+)", re.M)   # top level
IMPORT = re.compile(r"^import \{ ([^}]*) \} from '\./([\w]+)\.js';$", re.M)
# The browser globals eslint.config.mjs declares, in its list before .map
GLOBALS = re.compile(r"const browser = Object\.fromEntries\(\s*\[(.*?)\]\.map", re.S)


def test_every_module_imports_what_its_module_exports():
    sources = {f.stem: f.read_text(encoding="utf-8") for f in sorted(JS.glob("*.js"))}
    assert "core" in sources and "main" in sources
    exports = {m: set(EXPORT.findall(src)) for m, src in sources.items()}
    problems = []
    for m, src in sources.items():
        imported = {}
        for names, frm in IMPORT.findall(src):
            for name in (n.strip() for n in names.split(",")):
                if name not in exports.get(frm, set()):
                    problems.append(f"{m}.js imports {name} from {frm}.js, which doesn't export it")
                imported[name] = frm
        problems.extend(f"{m}.js both declares and imports {name}, which stops it loading"
                        for name in set(imported) & set(DECLARED.findall(src)))
    assert not IMPORT.findall(sources["core"]), "core.js must import nothing, so it loads first"
    assert problems == []
    globals_ = set(re.findall(r'"([\w$]+)"', GLOBALS.search((ROOT / "eslint.config.mjs").read_text(encoding="utf-8"))[1]))
    assert "document" in globals_ and not globals_ & set().union(*exports.values())
