"""The code passes both linters, through the commands scripts/lint.py runs. Each is skipped when its
linter isn't installed: ruff comes with uv sync, and ESLint with npm ci --ignore-scripts."""

import importlib.util
import subprocess
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("lint", Path(__file__).parents[1] / "scripts" / "lint.py")
lint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint)

pytestmark = pytest.mark.lint


@pytest.mark.parametrize("linter", list(lint.LINTERS))
def test_the_code_passes_the_linter(linter):
    if reason := lint.missing(linter):
        pytest.skip(reason)
    result = subprocess.run(lint.LINTERS[linter], cwd=lint.ROOT, capture_output=True, encoding="utf-8", errors="replace")
    assert result.returncode == 0, result.stdout + result.stderr
