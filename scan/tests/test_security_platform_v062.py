"""Platform-control regression tests; native execution must run on actual OS."""
import base64,importlib.util,json,pathlib,sys,tempfile,unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[2]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'tools'/file)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
class SecurityPlatformTests(unittest.TestCase):
    def test_android_missing_signature_fails(self):
        m=module('android_verify','verify_android_collector.py')
        with tempfile.TemporaryDirectory() as d:
            a=pathlib.Path(d)
            for x in ('bin','manifest','sig','key'):(a/x).write_bytes(b'garbage')
            with self.assertRaises(Exception):m.verify(a/'bin',a/'manifest',a/'sig',a/'key')
    def test_android_manifest_cannot_claim_unpinned_binary(self):
        m=module('android_verify2','verify_android_collector.py')
        # Signature check must happen before any trust in the unverified manifest.
        with tempfile.TemporaryDirectory() as d:
            a=pathlib.Path(d)
            (a/'key').write_text(base64.b64encode(b'\x00'*32).decode())
            (a/'sig').write_bytes(b'\x00'*64)
            (a/'manifest').write_text(json.dumps({'filename':'evil.exe','review':'approved'}))
            (a/'bin').write_bytes(b'evil')
            with self.assertRaises(Exception):m.verify(a/'bin',a/'manifest',a/'sig',a/'key')
    def test_mac_refuses_non_macos(self):
        m=module('mac_contained','macos_contained.py')
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(m.sys,'platform','linux'):
                with self.assertRaises(SystemExit):m.main(['--output',d,'--probe-only'])
    def test_probe_requires_child_and_parent(self):
        m=module('containment','containment_probe.py')
        with mock.patch.object(m,'blocked',return_value=False):
            out=m.probe()
            self.assertFalse(out['parent_ipv4_blocked'])
            self.assertFalse(out['parent_ipv6_blocked'])
    def test_windows_enforces_vm_and_refuses_allow_rules(self):
        txt=(ROOT/'tools'/'windows-vm-offline.ps1').read_text()
        self.assertIn('Get-CimInstance Win32_ComputerSystem',txt)
        self.assertIn('Get-NetFirewallRule -Direction Outbound -Action Allow',txt)
        self.assertIn('finally',txt)
if __name__=='__main__': unittest.main()
