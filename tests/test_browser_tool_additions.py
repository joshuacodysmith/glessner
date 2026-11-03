"""The Tools page's line for a tool whose runs had none of the app's additions, in a real browser. It drives the installed
Microsoft Edge through Playwright, as test_browser_smoke does, and is skipped without it."""

import pytest
from test_browser_smoke import browser, case_menu, served_page  # noqa: F401
from test_server import fake_tool_case

from glessner.runner import finish_run, start_run
from glessner.tools import Composed

pytestmark = pytest.mark.browser


def test_a_run_without_the_apps_additions_says_so_and_how_to_load_their_rows(browser, synthetic_case, tmp_path):  # noqa: F811
    """The stand-in tool composes a batch file from the app's. Its run on DC01 was made before it did, so the line names
    that host; its run on DESKTOP holds the composed batch."""
    specs, detected = fake_tool_case(synthetic_case, tmp_path)
    spec = specs["fake"].__class__(**{**specs["fake"].__dict__,
                                      "compose": {"batch_file": Composed("batch.reb", tmp_path / "additions.reb")}})
    tool = detected["fake"].__class__(spec, detected["fake"].executable, detected["fake"].version)
    for name, host, outputs in (("a", "DC01", ["out.csv"]), ("b", "DESKTOP", ["out.csv", "composed_batch.reb"])):
        record, folder = start_run(synthetic_case, "fake", name, tool_version="1.0", host=host, inputs=["x"],
                                   status="ok", loaded_rows=10,
                                   outputs=[{"path": path, "sha256": "ab" * 32} for path in outputs])
        finish_run(folder, record)

    def setup(app):
        app.tool_cache = ({"fake": spec}, {"fake": tool})

    for p in served_page(browser, synthetic_case, setup=setup):
        case_menu(p, "toolsButton")
        line = p.locator("#details tr[data-tool='fake'] .tools-additions")
        assert line.inner_text() == ("Fake ran without Glessner additions on DC01. Run Fake again to load the added "
                                     "rows.")
        assert "warn" in line.get_attribute("class").split()
