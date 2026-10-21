"""The build identifier: the release version, which pyproject.toml alone holds and the package reads from
its installed metadata, plus the commit the code came from, as a PEP 440 local label: 0.2.0+abc1234, or
0.2.0+abc1234.dirty when tracked files under the package differ from that commit. The report, the audit trail
and its export, the start page, `--version`, the built-in tools and imports as a tool version, and the journal's
case_open entries carry it.
"""

from __future__ import annotations

import functools
import shutil
import subprocess
import time
from pathlib import Path

from . import __version__

# A release build writes its build string here, such as "0.2.0+abc1234", and build_id() then gives it as it is, without
# asking git. Empty in a source checkout.
BAKED_BUILD = ""
PACKAGE_DIR = Path(__file__).resolve().parent
GIT_TIMEOUT_S = 3   # for build_id's git commands together


@functools.cache
def build_id() -> str:
    """The build identifier, worked out once per process, when first asked for. Without git, outside a checkout, or
    when git fails or its commands take longer than GIT_TIMEOUT_S together, the release version alone."""
    if BAKED_BUILD:
        return BAKED_BUILD
    deadline = time.monotonic() + GIT_TIMEOUT_S
    commit = _git(deadline, "rev-parse", "--short=7", "HEAD")
    # The package must be one the checkout tracks: a copy installed inside another checkout, such as a .venv in a
    # repository, would otherwise take that checkout's commit.
    if not commit or _git(deadline, "ls-files", "--error-unmatch", "--", "__init__.py") is None:
        return __version__
    # Only the package's own files count: the repository holds a whole workspace, whose other changes would make every
    # build read dirty. No optional locks, so a running app never holds the index's lock against the analyst's git.
    changed = _git(deadline, "--no-optional-locks", "status", "--porcelain", "--untracked-files=no", "--", ".")
    if changed is None:
        return __version__
    local = commit.strip() + (".dirty" if changed.strip() else "")
    return f"{__version__}{'.' if '+' in __version__ else '+'}{local}"   # 0+unknown has its local label already


def _git(deadline: float, *args: str) -> str | None:
    """git's output for `args`, run in the package's folder without a shell, or None when git is missing, fails, or
    hasn't finished by `deadline`. The package keeps shutil.which out of the current folder (__init__.py)."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        proc = subprocess.Popen([git, *args], cwd=PACKAGE_DIR, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, errors="replace")
    except OSError:
        return None
    try:
        out, _ = proc.communicate(timeout=max(deadline - time.monotonic(), 0))
    except subprocess.TimeoutExpired:
        # Killed without the second communicate() that subprocess.run makes, which on Windows waits for every process
        # holding git's output open, however long it runs: Git for Windows' cmd\git.exe runs the real git as a child.
        # Such a child is left to finish on its own.
        proc.kill()
        proc.wait()
        return None
    return out if proc.returncode == 0 else None
