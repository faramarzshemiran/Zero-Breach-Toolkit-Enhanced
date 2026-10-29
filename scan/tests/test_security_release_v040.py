"""Production-profile regression tests, no live network/device interaction."""
import importlib.util
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scan'))
from zbtriage.security_policy import validate_requested_operation, SecurityPolicyError
from types import SimpleNamespace

def load(name, path):
    spec=importlib.util.spec_from_file_location(name,str(path))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
launcher=load('secure_run',ROOT/'tools/secure_run.py')
update=load('updater',ROOT/'tools/update_indicators.py')
manifest=load('manifest_verifier',ROOT/'tools/verify_manifest.py')
class SecurityReleaseTests(unittest.TestCase):
    def test_strict_linux_namespace_includes_children(self):
        cmd=launcher.build_command('offline-strict',['--quick'],system='linux',executable='/usr/bin/python3')
        self.assertEqual(cmd[1:3],['--net','--'])
        self.assertIn('--quick',cmd)
    def test_windows_fails_closed(self):
        with self.assertRaises(RuntimeError): launcher.build_command('offline-strict',[],system='win32')
    def test_macos_fails_closed(self):
        with self.assertRaises(RuntimeError): launcher.build_command('offline-strict',[],system='darwin')
    def test_collector_rejected_even_with_consent(self):
        with self.assertRaises(SecurityPolicyError):
            validate_requested_operation(SimpleNamespace(collect_android='.',allow_external_collector=True,high_assurance=False))
    def test_launcher_rejects_updates_and_collector(self):
        for flag in ['--update','--collect-android','--allow-external-collector','--latest']:
            with self.subTest(flag=flag):
                with self.assertRaises(ValueError): launcher.build_command('offline-standard',[flag])
    def test_standard_enforces_no_feeds(self):
        self.assertIn('--no-feeds',launcher.build_command('offline-standard',[]))
    def test_manifest_integrity(self):
        self.assertEqual(manifest.verify(),[])
    def test_updater_rejects_extra_options(self):
        with self.assertRaises(SystemExit): update.main(['--latest'])
if __name__=='__main__': unittest.main()
