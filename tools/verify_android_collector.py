#!/usr/bin/env python3
"""Offline collector authentication: signed trusted manifest + pinned upstream SHA256.
No binary is launched or downloaded. Manifest is signed by a separately trusted
reviewer; this cannot attest that the upstream build is benign.
"""
import argparse,base64,hashlib,json,pathlib,sys

def verify(binary,manifest,signature,key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    raw = pathlib.Path(manifest).read_bytes()
    pub = base64.b64decode(pathlib.Path(key).read_text().strip(),validate=True)
    sig = pathlib.Path(signature).read_bytes()
    if len(pub)!=32 or len(sig)!=64: raise ValueError('incorrect Ed25519 key/signature length')
    Ed25519PublicKey.from_public_bytes(pub).verify(sig,raw)
    data=json.loads(raw)
    if data.get('schema') != 'zero-breach-collector-attestation-v1': raise ValueError('unexpected manifest schema')
    from pathlib import Path
    base=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(base/'scan'))
    from zbtriage.phoneguide import _PHONE_ASSETS
    pinned={name:digest for name,digest in _PHONE_ASSETS.values()}
    name=pathlib.Path(binary).name
    if name not in pinned or data.get('filename')!=name: raise ValueError('collector name not pinned')
    if data.get('sha256')!=pinned[name]: raise ValueError('attested digest differs from pinned release')
    if data.get('review') != 'approved' or not data.get('reviewer') or not data.get('source_commit'):
        raise ValueError('missing explicit review or source revision')
    h=hashlib.sha256()
    with open(binary,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    if h.hexdigest()!=pinned[name]: raise ValueError('local collector digest mismatch')
    return {'collector':name,'sha256':h.hexdigest(),'reviewer':data['reviewer'],'source_commit':data['source_commit']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('binary','manifest','signature','trusted-public-key'):p.add_argument('--'+arg,required=True)
    a=p.parse_args()
    try:
        print(json.dumps(verify(a.binary,a.manifest,a.signature,a.trusted_public_key),indent=2))
        return 0
    except Exception as e:
        print('COLLECTOR NOT AUTHENTICATED:',str(e),file=sys.stderr)
        return 3
if __name__=='__main__':sys.exit(main())
