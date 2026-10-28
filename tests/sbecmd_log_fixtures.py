"""SBECmd's record of a run as its builds write it, for tests that read a run's hive names from it.

Builds before 2026.10 write !SBECmd_Messages.txt. From 2026.10, <UTC yyyyMMddHHmmss>_SBECmd_<version>_ConsoleLog.txt takes
its place. Both hold the same lines, with CRLF line ends, and each names itself in one line.
"""

MESSAGES_NAME = "!SBECmd_Messages.txt"
CONSOLE_LOG_NAME = "20261025181337_SBECmd_2026.10.2_ConsoleLog.txt"


def _run_lines(hive: str, exported: str) -> list[str]:
    """The lines of a run on one hive, from the hive's "Processing" line to the totals."""
    return [
        f"[01:13:37.283 INF] Processing {hive}",
        "[01:13:37.312 WRN] Registry hive is dirty and no transaction logs were found in the same directory. "
        "Data may be missing! Continuing anyways...",
        "[01:13:37.723 INF] Parse time: 0.28 seconds",
        "[01:13:37.727 INF] Total ShellBags found: 25",
        "[01:13:37.727 INF] Totals by bag type",
        "[01:13:37.728 INF] Directory: 16",
        f"[01:13:37.728 INF] Finished processing {hive}",
        f"[01:13:37.728 INF] Exported to: {exported}",
        "[01:13:37.728 INF] " + "-" * 69,
        "[01:13:37.728 INF] Processing complete!",
        "[01:13:37.729 INF] Processed 1 file in 0.28 seconds!",
        "[01:13:37.729 INF] Total ShellBags found: 25",
    ]


def messages_text(hive: str, exported: str, folder: str = r"C:\out") -> str:
    """The messages file of a build before 2026.10 for a run that read one hive and wrote one CSV."""
    head = ["[01:13:38.371 INF] SBECmd version 2026.5.0", "",
            f"[01:13:38.397 INF] All messages will be saved to {folder}\\{MESSAGES_NAME}"]
    return "\r\n".join([*head, *_run_lines(hive, exported), "", ""])


def console_log_text(hive: str, exported: str, folder: str = r"C:\out", name: str = CONSOLE_LOG_NAME) -> str:
    """The console log of a 2026.10 build for a run that read one hive and wrote one CSV."""
    head = ["[01:13:37.234 INF] SBECmd version 2026.10.2", "",
            f"[01:13:37.259 INF] Command line: -d {folder}\\in --csv {folder} --nl",
            f"[01:13:37.263 INF] Console log: {folder}\\{name}"]
    return "\r\n".join([*head, *_run_lines(hive, exported), "", ""])
