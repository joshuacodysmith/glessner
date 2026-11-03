"""Build the rule file the app's Suricata runs use, from an unpacked ET Open rule set.

Suricata's Windows package lists ET Open's rule files by name in suricata.yaml, but the list drifts from what ET ships:
in ET Open 11310, two listed files don't exist and nine shipped files, such as emerging-exploit_kit.rules, aren't
listed. So the app loads one file, as suricata-update would make it: every rule file in the set except
emerging-deleted.rules and emerging-retired.rules, which hold rules ET has withdrawn. The registry entry runs Suricata
with -S on that file, and reads the set's version from beside it.

Usage: python scripts/suricata_rules.py <ET Open folder holding rules/ and version.txt> <folder holding suricata.exe>
Writes, in <folder holding suricata.exe>/rules/: suricata.rules, classification.config (ET's, which names its
classtypes), and et-open-version.txt. It writes nothing when the set has no rule files or no classification.config. It
writes all three to temporary files first, then replaces classification.config, suricata.rules, and et-open-version.txt
in that order, so a build that fails before the rule file is replaced leaves the earlier rules in force with the
version file still naming them. A build that fails also removes the temporary files it wrote.
"""

import shutil
import sys
from pathlib import Path

WITHDRAWN = {"emerging-deleted.rules", "emerging-retired.rules"}
ACTIONS = ("alert ", "drop ", "pass ", "reject ")


def main(et: Path, suricata: Path) -> int:
    rules_dir = et / "rules"
    files = sorted(p for p in rules_dir.glob("*.rules") if p.name not in WITHDRAWN)
    if not files:
        print(f"No .rules files in {rules_dir}", file=sys.stderr)
        return 1
    classification = rules_dir / "classification.config"
    if not classification.is_file():
        print(f"No classification.config in {rules_dir}", file=sys.stderr)
        return 1
    out_dir = suricata / "rules"
    out_dir.mkdir(exist_ok=True)
    active = 0
    rules_tmp = out_dir / "suricata.rules.tmp"
    classification_tmp = out_dir / "classification.config.tmp"
    version_tmp = out_dir / "et-open-version.txt.tmp"
    try:
        with rules_tmp.open("w", encoding="utf-8", newline="\n") as out:
            for p in files:
                out.write(f"# --- {p.name}\n")
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    out.write(line + "\n")
                    active += line.startswith(ACTIONS)
        shutil.copy2(classification, classification_tmp)
        version = (et / "version.txt").read_text(encoding="utf-8").strip() if (et / "version.txt").exists() else "unknown"
        version_tmp.write_text(f"ET Open {version}\n", encoding="utf-8")
        classification_tmp.replace(out_dir / "classification.config")
        rules_tmp.replace(out_dir / "suricata.rules")
        # Each run records the version file's text as its rules version, so it changes only after the rules it names
        version_tmp.replace(out_dir / "et-open-version.txt")
    finally:
        # A finished build has renamed every temporary file away, so only a build that failed has anything to remove
        for tmp in (rules_tmp, classification_tmp, version_tmp):
            tmp.unlink(missing_ok=True)
    print(f"{out_dir / 'suricata.rules'}: {active:,} active rules from {len(files)} files, ET Open {version}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
