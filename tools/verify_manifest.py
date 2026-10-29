#!/usr/bin/env python3
"""Compare local source with build-time manifest; a hash list is NOT a signature."""
import hashlib
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT/'RELEASE-SHA256.json'
def verify():
    expected = json.loads(MANIFEST.read_text(encoding='utf-8'))
    errors=[]
    for name, digest in expected['files'].items():
        path=ROOT/name
        if path.is_symlink() or not path.is_file():
            errors.append(name+': missing or symlink')
        elif hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            errors.append(name+': changed')
    return errors
if __name__ == '__main__':
    failures=verify()
    for failure in failures:
        print(failure)
    print('Manifest check:', 'FAILED' if failures else 'OK (integrity only; not publisher authentication)')
    raise SystemExit(bool(failures))
