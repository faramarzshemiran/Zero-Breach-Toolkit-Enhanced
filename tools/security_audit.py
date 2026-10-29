#!/usr/bin/env python3
"""Non-invasive audit of repository and system prerequisites. No networking."""
import argparse
import hashlib
import json
import os
import platform
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for data in iter(lambda: f.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()

def audit():
    inventory = {}
    for path in sorted((ROOT / "scan").rglob("*.py")):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("symbolic-link source is not trusted: " + str(path))
        inventory[str(path.relative_to(ROOT))] = sha256(path)
    return {"python": sys.version.split()[0], "platform": platform.platform(),
            "root": str(ROOT), "code_files": len(inventory), "sha256": inventory,
            "os_egress_isolation_proven": False, "android_collector_attested": False,
            "independent_penetration_test": False}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", metavar="PATH", help="save inventory (path is local; contains filenames)")
    ap.add_argument("--require-production", action="store_true", help="fail if mandatory production attestations absent")
    args = ap.parse_args()
    result = audit()
    output = json.dumps(result, indent=2) + "\n"
    if args.json:
        target = Path(args.json)
        if target.is_symlink():
            ap.error("will not write through a symlink")
        with target.open("w", encoding="utf-8") as f:
            f.write(output)
        if os.name == "posix":
            target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    else:
        print(output)
    if args.require_production and not all(result[k] for k in (
            "os_egress_isolation_proven", "android_collector_attested", "independent_penetration_test")):
        print("PRODUCTION GATE FAILED: independent attestation is missing", file=sys.stderr)
        return 3
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
