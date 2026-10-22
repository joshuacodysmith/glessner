"""Build the rule file the app's Suricata runs use, from an unpacked ET Open rule set.

Suricata's Windows package lists ET Open's rule files by name in suricata.yaml, but the list drifts from what ET ships:
in ET Open 11310, two listed files don't exist and nine shipped files, such as emerging-exploit_kit.rules, aren't
listed. So the app loads one file, as suricata-update would make it: every rule file in the set except
emerging-deleted.rules and emerging-retired.rules, which hold rules ET has withdrawn. The registry entry runs Suricata
with -S on that file, and reads the set's version from beside it.

Usage: python scripts/suricata_rules.py <ET Open folder holding rules/ and version.txt> <folder holding suricata.exe>
Writes, in <folder holding suricata.exe>/rules/: suricata.rules, classification.config (ET's, which names its
classtypes), and et-open-version.txt. It writes nothing when the set has no rule files or no classification.config, and
it replaces suricata.rules last, so a build that fails partway leaves the earlier rules in force. A build that fails
also removes the temporary files it wrote.
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
    try:
        with rules_tmp.open("w", encoding="utf-8", newline="\n") as out:
            for p in files:
                out.write(f"# --- {p.name}\n")
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    out.write(line + "\n")
                    active += line.startswith(ACTIONS)
        shutil.copy2(classification, classification_tmp)
        classification_tmp.replace(out_dir / "classification.config")
        version = (et / "version.txt").read_text(encoding="utf-8").strip() if (et / "version.txt").exists() else "unknown"
        (out_dir / "et-open-version.txt").write_text(f"ET Open {version}\n", encoding="utf-8")
        rules_tmp.replace(out_dir / "suricata.rules")
    finally:
        # A finished build has renamed both files away, so only a build that failed has anything left to remove
        rules_tmp.unlink(missing_ok=True)
        classification_tmp.unlink(missing_ok=True)
    print(f"{out_dir / 'suricata.rules'}: {active:,} active rules from {len(files)} files, ET Open {version}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
