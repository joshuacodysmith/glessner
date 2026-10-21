"""Glessner: run forensic tools on a triage collection and review one lane timeline."""

import importlib.metadata
import importlib.util
import os
import sys

# Without this variable, Windows looks for a program in the current folder before PATH, so shutil.which("git") or a
# tool's name could find a planted copy in the folder the app started from, such as an evidence folder, and run it.
# Python's shutil documentation names the variable for this. The tools the app runs inherit it.
os.environ.setdefault("NoDefaultCurrentDirectoryInExePath", "1")


def _release_version() -> str:
    """The release version, which pyproject.toml alone holds, from the installed package's metadata. uv
    installs the project editable and writes the metadata at uv sync, so a changed version shows after the next sync."""
    try:
        return importlib.metadata.version("glessner")
    except importlib.metadata.PackageNotFoundError:   # the source tree run without installing it
        return "0+unknown"


__version__ = _release_version()

# DuckDB 1.5.6's Python client tries to import pandas twice for each value it binds as a query parameter, to compare
# the value with pandas' NaT and NA, and doesn't keep a failed import. pandas isn't installed, so every try searched the
# import path again: on Python 3.14, `SELECT ?` took 1.8 ms against 0.2 ms for `SELECT 1`, and the four parameters of
# every view query (queries.window_where) 6.2 ms. With None in sys.modules, Python fails the import at once, and four
# parameters took 0.29 ms when measured. An installed pandas is left alone.
if importlib.util.find_spec("pandas") is None:
    sys.modules["pandas"] = None
