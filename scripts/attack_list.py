"""Make the app's ATT&CK technique list from MITRE's Enterprise ATT&CK STIX data.

Usage: python -I scripts/attack_list.py <enterprise-attack.json> [<output file>]

The input is the enterprise-attack.json of a release of github.com/mitre-attack/attack-stix-data, downloaded into a
folder of its own and read as untrusted data. The output, src/glessner/attack_techniques.json by default, holds what
the finding form's pick list and the server's check need: each current technique and sub-technique's ID, its name (a
sub-technique's as "Technique: Sub-technique", as attack.mitre.org writes it), and its tactic IDs; the tactics in the
matrix's order; and each revoked ID with the current technique MITRE revoked it in favor of. Revoked and deprecated
techniques aren't listed. It records the ATT&CK version, the release's URL, the input's SHA-256, and MITRE's copyright
line and license, which every copy must carry.

Check the copyright line and license below against https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
before each new release. The standard library alone, so a reviewer can read all of it.
"""

import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

OUTPUT = Path(__file__).resolve().parents[1] / "src" / "glessner" / "attack_techniques.json"
RELEASE = "https://github.com/mitre-attack/attack-stix-data/releases/download/v{version}/enterprise-attack.json"
COPYRIGHT = ("© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE "
             "Corporation.")
LICENSE = ("The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for "
           "research, development, and commercial purposes. Any copy you make for such purposes is authorized provided "
           "that you reproduce MITRE's copyright designation and this license in any such copy.")
ABOUT = ("Enterprise ATT&CK's current techniques and sub-techniques, for a finding's ATT&CK field and the tag picker's "
         "technique box, made by scripts/attack_list.py from MITRE's STIX data. Each technique is [ID, name, tactic IDs]; a "
         "sub-technique's name is 'Technique: Sub-technique', as attack.mitre.org writes it. The tactics are in the "
         "matrix's order. 'revoked' maps each revoked ID to the current technique MITRE revoked it in favor of. Revoked "
         "and deprecated techniques aren't in the list.")
TECHNIQUE = re.compile(r"T\d{4}(\.\d{3})?")
TACTIC = re.compile(r"TA\d{4}")
NAME = re.compile(r"[^\x00-\x1f\x7f]{1,120}")


def attack_id(obj: dict) -> str:
    """The object's ATT&CK ID, from its mitre-attack external reference."""
    refs = [r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"]
    if len(refs) != 1 or not isinstance(refs[0].get("external_id"), str):
        raise ValueError(f"{obj.get('id')} has no single mitre-attack ID")
    return refs[0]["external_id"]


def current(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def build(bundle: dict, sha256: str) -> dict:
    objects = bundle.get("objects")
    if bundle.get("type") != "bundle" or not isinstance(objects, list):
        raise ValueError("not a STIX bundle")
    collections = [o for o in objects if o.get("type") == "x-mitre-collection"]
    matrices = [o for o in objects if o.get("type") == "x-mitre-matrix" and current(o)]
    if len(collections) != 1 or len(matrices) != 1 or collections[0].get("name") != "Enterprise ATT&CK":
        raise ValueError("expected one Enterprise ATT&CK collection and one current matrix")
    version = str(collections[0].get("x_mitre_version"))
    if not re.fullmatch(r"\d{1,3}\.\d{1,3}", version):
        raise ValueError(f"unexpected version {version!r}")
    by_ref = {o["id"]: o for o in objects if isinstance(o.get("id"), str)}

    # The tactics, in the matrix's order, and each one's shortname, which a technique's kill-chain phase names
    tactics, shortnames = [], {}
    for ref in matrices[0].get("tactic_refs", []):
        t = by_ref[ref]
        tid, name = attack_id(t), t["name"]
        if not (TACTIC.fullmatch(tid) and NAME.fullmatch(name) and current(t)):
            raise ValueError(f"unexpected tactic {tid} {name!r}")
        tactics.append([tid, name])
        shortnames[t["x_mitre_shortname"]] = tid
    order = [tid for tid, _ in tactics]

    patterns = [o for o in objects if o.get("type") == "attack-pattern"]
    live = {}
    for o in patterns:
        if not current(o):
            continue
        tid = attack_id(o)
        if not TECHNIQUE.fullmatch(tid) or not NAME.fullmatch(o.get("name", "")) or tid in live:
            raise ValueError(f"unexpected or repeated technique {tid}")
        if bool(o.get("x_mitre_is_subtechnique")) != ("." in tid):
            raise ValueError(f"{tid}: its sub-technique flag doesn't match its ID")
        names = [p.get("phase_name") for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        if any(n not in shortnames for n in names):
            raise ValueError(f"{tid} names a tactic the matrix doesn't")
        phases = {shortnames[n] for n in names}
        if not phases:
            raise ValueError(f"{tid} names no tactic")
        live[tid] = (o["name"], sorted(phases, key=order.index))
    techniques = []
    for tid in sorted(live):
        name, phases = live[tid]
        if "." in tid:
            parent = tid.split(".")[0]
            if parent not in live:
                raise ValueError(f"{tid}'s parent {parent} isn't current")
            name = f"{live[parent][0]}: {name}"
        techniques.append([tid, name, phases])

    # Each revoked ID, followed through revoked-by to the current technique it ends at; one that ends nowhere current, or
    # whose ID a current technique uses, is left out
    revoked_by = {o["source_ref"]: o["target_ref"] for o in objects
                  if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by" and current(o)}
    revoked = {}
    for o in patterns:
        if not o.get("revoked"):
            continue
        old, ref, seen = attack_id(o), o["id"], set()
        while ref in revoked_by and ref not in seen:
            seen.add(ref)
            ref = revoked_by[ref]
        target = by_ref.get(ref)
        if target is not None and current(target) and old not in live and TECHNIQUE.fullmatch(old):
            new = attack_id(target)
            if new in live:
                revoked[old] = new
    return {"about": ABOUT,
            "attack": {"name": "Enterprise ATT&CK", "version": version, "modified": collections[0].get("modified"),
                       "source": RELEASE.format(version=version), "sha256": sha256,
                       "made": datetime.now(UTC).strftime("%Y-%m-%d")},
            "copyright": COPYRIGHT, "license": LICENSE, "tactics": tactics, "techniques": techniques,
            "revoked": dict(sorted(revoked.items()))}


def write(data: dict, out: Path) -> None:
    """One technique, tactic, or revoked ID per line, so a new release's changes read as a short diff."""
    def line(value):
        return json.dumps(value, ensure_ascii=False)
    head = {k: data[k] for k in ("about", "attack", "copyright", "license")}
    lines = ["{"] + [f"  {line(k)}: {line(v)}," for k, v in head.items()]
    for key in ("tactics", "techniques"):
        lines += [f"  {line(key)}: ["] + [f"    {line(row)}," for row in data[key]]
        lines[-1] = lines[-1].rstrip(",")
        lines.append("  ],")
    lines += ['  "revoked": {'] + [f"    {line(k)}: {line(v)}," for k, v in data["revoked"].items()]
    lines[-1] = lines[-1].rstrip(",")
    lines += ["  }", "}"]
    text = "\n".join(lines) + "\n"
    if json.loads(text) != data:
        raise AssertionError("the written list doesn't read back as built")
    tmp = out.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    tmp.replace(out)


def main(source: Path, out: Path) -> int:
    raw = source.read_bytes()
    data = build(json.loads(raw), hashlib.sha256(raw).hexdigest())
    write(data, out)
    subs = sum("." in row[0] for row in data["techniques"])
    print(f"{out}: Enterprise ATT&CK {data['attack']['version']}, {len(data['techniques'])} techniques "
          f"({len(data['techniques']) - subs} techniques, {subs} sub-techniques), {len(data['tactics'])} tactics, "
          f"{len(data['revoked'])} revoked IDs, {out.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2]) if len(sys.argv) == 3 else OUTPUT))
