import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('containment_probe_063', ROOT/'tools'/'containment_probe.py')
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class Containment063Tests(unittest.TestCase):
    def test_four_distinct_egress_targets(self):
        self.assertEqual(len(mod.TARGETS),4)
        self.assertEqual(len({x[1] for x in mod.TARGETS}),4)
    def test_blocked_connection(self):
        with patch.object(mod.socket, 'socket') as sock:
            sock.return_value.__enter__.return_value.connect_ex.return_value=101
            self.assertTrue(mod.blocked('1.1.1.1',mod.socket.AF_INET,443))
    def test_open_connection_is_failure(self):
        with patch.object(mod.socket, 'socket') as sock:
            sock.return_value.__enter__.return_value.connect_ex.return_value=0
            self.assertFalse(mod.blocked('1.1.1.1',mod.socket.AF_INET,443))
    def test_windows_disconnected_adapter_gate(self):
        source=(ROOT/'tools'/'windows-vm-offline.ps1').read_text()
        self.assertIn('Get-NetAdapter',source)
        self.assertIn('Disconnect ALL VM network adaptors',source)
    def test_macos_refuses_root(self):
        source=(ROOT/'tools'/'macos_contained.py').read_text()
        self.assertIn("os.geteuid() == 0",source)
