"""Run the project's linters: ruff over the Python in src, tests, and scripts, with its settings in pyproject.toml, and
ESLint over the page's ES modules, with eslint.config.mjs.

Usage, from the project folder: uv run python scripts/lint.py [ruff] [eslint]
With no name it runs both. Exits 1 when a linter reports a problem and 2 when one isn't installed: ruff comes with
uv sync, and ESLint with npm ci --ignore-scripts. tests/test_lint.py runs the same commands in the test suite.
"""

import shutil
import subprocess
import sys
from importlib.util import find_spec
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ESLINT = ROOT / "node_modules" / "eslint" / "bin" / "eslint.js"
LINTERS = {
    "ruff": [sys.executable, "-m", "ruff", "check", "src", "tests", "scripts", "pyproject.toml"],
    "eslint": ["node", str(ESLINT), "src/glessner/static/js"],
}


def missing(linter: str) -> str:
    """Why the linter can't run here, or "" when it can."""
    if linter == "ruff":
        return "" if find_spec("ruff") else "ruff isn't installed; run uv sync"
    if not shutil.which("node"):
        return "ESLint needs Node.js, which isn't on PATH"
    return "" if ESLINT.is_file() else "ESLint isn't installed; run npm ci --ignore-scripts"


def main(names: list[str]) -> int:
    if unknown := [n for n in names if n not in LINTERS]:
        print(f"Unknown linter {', '.join(unknown)}; choose from {', '.join(LINTERS)}.", file=sys.stderr)
        return 2
    status = 0
    for name in names or LINTERS:
        if reason := missing(name):
            print(f"{name}: {reason}", file=sys.stderr)
            status = 2
        elif subprocess.run(LINTERS[name], cwd=ROOT).returncode:
            status = max(status, 1)
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
