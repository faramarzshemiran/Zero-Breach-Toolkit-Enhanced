import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class ReleaseSecurityTests(unittest.TestCase):
    def test_signed_release_rejects_invalid_signature(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            self.skipTest('cryptography optional dependency unavailable')
        import base64, json
        from cryptography.hazmat.primitives import serialization
        mod = load('verify_signed_release')
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)
            (p/'file.txt').write_text('hello')
            import hashlib
            m = json.dumps({'files': {'file.txt': hashlib.sha256(b'hello').hexdigest()}}).encode()
            (p/'manifest').write_bytes(m)
            key = Ed25519PrivateKey.generate()
            pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            (p/'key').write_text(base64.b64encode(pub).decode())
            (p/'sig').write_text(base64.b64encode(key.sign(m)).decode())
            self.assertEqual(mod.verify(p, p/'manifest', p/'sig', p/'key'), 1)
            (p/'file.txt').write_text('tampered')
            with self.assertRaises(ValueError):
                mod.verify(p, p/'manifest', p/'sig', p/'key')
            (p/'file.txt').write_text('hello')
            (p/'sig').write_text(base64.b64encode(b'\x00'*64).decode())
            with self.assertRaises(Exception):
                mod.verify(p, p/'manifest', p/'sig', p/'key')

    def test_evidence_vault_authenticated_roundtrip(self):
        try:
            import cryptography
        except ImportError:
            self.skipTest('cryptography optional dependency unavailable')
        vault=load('evidence_vault')
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            (p/'src').write_bytes(b'confidential evidence')
            vault.transform(p/'src', p/'encrypted', 'test passphrase long enough')
            self.assertNotIn(b'confidential evidence', (p/'encrypted').read_bytes())
            vault.transform(p/'encrypted', p/'decrypted', 'test passphrase long enough', decrypt=True)
            self.assertEqual((p/'decrypted').read_bytes(), b'confidential evidence')
            with self.assertRaises(Exception):
                vault.transform(p/'encrypted', p/'bad', 'wrong passphrase long enough', decrypt=True)
            with self.assertRaises(FileExistsError):
                vault.transform(p/'src', p/'encrypted', 'test passphrase long enough')
