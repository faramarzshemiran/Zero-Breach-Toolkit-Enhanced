#!/usr/bin/env python3
"""Verify a publisher's Ed25519 signature and a full SHA-256 release manifest.
The trusted public key must come from an independently authenticated channel;
never treat a public key bundled alongside the archive as authenticated.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import sys

def verify(root, manifest_path, signature_path, public_key_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    root = pathlib.Path(root).resolve()
    manifest_bytes = pathlib.Path(manifest_path).read_bytes()
    signature = base64.b64decode(pathlib.Path(signature_path).read_text().strip(), validate=True)
    key = base64.b64decode(pathlib.Path(public_key_path).read_text().strip(), validate=True)
    Ed25519PublicKey.from_public_bytes(key).verify(signature, manifest_bytes)
    entries = json.loads(manifest_bytes)['files']
    if not isinstance(entries, dict) or not entries:
        raise ValueError('invalid or empty manifest')
    for name, digest in entries.items():
        rel = pathlib.PurePosixPath(name)
        if rel.is_absolute() or '..' in rel.parts or not isinstance(digest, str) or len(digest) != 64:
            raise ValueError('unsafe signed manifest entry')
        path = root.joinpath(*rel.parts)
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError('missing, redirected or unsafe file: ' + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('hash mismatch: ' + name)
    return len(entries)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', default='.')
    p.add_argument('--manifest', required=True)
    p.add_argument('--signature', required=True)
    p.add_argument('--trusted-public-key', required=True)
    a = p.parse_args()
    try:
        n = verify(a.root, a.manifest, a.signature, a.trusted_public_key)
    except Exception as exc:
        print('RELEASE REJECTED: '+str(exc), file=sys.stderr)
        return 2
    print('Signature and', n, 'file digests verified against independently supplied key')
    return 0
if __name__ == '__main__':
    sys.exit(main())
