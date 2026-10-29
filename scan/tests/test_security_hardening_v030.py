"""Hostile-path and release gate regression tests; no network connections."""
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scan"))
from zbtriage.report import write_json

class HardeningTests(unittest.TestCase):
    def test_original_launcher_version(self):
        c = subprocess.run([sys.executable, '-X', 'utf8', 'scan/zero-breach-toolkit.py', '--version'], cwd=ROOT,
                           capture_output=True, text=True, timeout=20)
        self.assertEqual(c.returncode, 0, c.stderr)
        self.assertIn('0.6.2-containment-validation', c.stdout)

    def test_report_rejects_directory_destination(self):
        with tempfile.TemporaryDirectory() as base:
            with self.assertRaises(OSError):
                write_json({}, base)

    def test_report_rejects_link_destination(self):
        with tempfile.TemporaryDirectory() as base:
            outside = Path(base) / 'outside'
            outside.write_text('secret')
            dest = Path(base) / 'link'
            try: dest.symlink_to(outside)
            except (OSError, NotImplementedError): self.skipTest('symlinks unavailable')
            with self.assertRaises(OSError): write_json({'x': 1}, str(dest))
            self.assertEqual(outside.read_text(), 'secret')

    @unittest.skipUnless(os.name == 'posix', 'POSIX mode security')
    def test_private_directory_policy(self):
        with tempfile.TemporaryDirectory() as base:
            directory = Path(base) / 'private'
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            dest = directory / 'report.json'
            write_json({'a': 'b'}, str(dest), require_private_dir=True)
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
            directory.chmod(0o755)
            with self.assertRaises(PermissionError):
                write_json({'a': 'c'}, str(dest), require_private_dir=True)

    def test_security_audit_production_gate(self):
        proc = subprocess.run([sys.executable, 'tools/security_audit.py', '--require-production'],
                              cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 3)
        self.assertIn('PRODUCTION GATE FAILED', proc.stderr)

if __name__ == '__main__': unittest.main()
