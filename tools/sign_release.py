#!/usr/bin/env python3
"""Offline Ed25519 signing tool. Creates signature over canonical release JSON.
Private key never distributed. Requires owner-managed PEM Ed25519 private key.
The corresponding public key fingerprint must be published via independent trusted channel.
"""
import argparse,base64,hashlib,json,pathlib,sys

def sign(root,key_path,manifest_path,signature_path):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    root=pathlib.Path(root).resolve()
    outputs={pathlib.Path(manifest_path).resolve(),pathlib.Path(signature_path).resolve()}
    files={}
    for folder in ('scan','tools','iocs'):
        for p in sorted((root/folder).rglob('*')):
            if not p.is_file() or p.is_symlink() or '__pycache__' in p.parts or p.suffix=='.pyc': continue
            if p.resolve() in outputs: continue
            files[p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
    if not files: raise ValueError('no files to sign')
    key=load_pem_private_key(pathlib.Path(key_path).read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey): raise ValueError('an Ed25519 signing key is required')
    data=(json.dumps({'files':files},sort_keys=True,indent=2)+'\n').encode('utf-8')
    manifest=pathlib.Path(manifest_path);signature=pathlib.Path(signature_path)
    for p in (manifest,signature):
        if p.exists(): raise FileExistsError('refusing overwrite: '+str(p))
    manifest.write_bytes(data)
    signature.write_text(base64.b64encode(key.sign(data)).decode('ascii')+'\n',encoding='ascii')
    return len(files)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',default='.');p.add_argument('--private-key',required=True)
    p.add_argument('--manifest',required=True);p.add_argument('--signature',required=True)
    a=p.parse_args()
    try:print('Signed',sign(a.root,a.private_key,a.manifest,a.signature),'files')
    except (ValueError,OSError,TypeError) as e:print('Signing rejected:',e,file=sys.stderr);return 2
    return 0
if __name__=='__main__':sys.exit(main())
