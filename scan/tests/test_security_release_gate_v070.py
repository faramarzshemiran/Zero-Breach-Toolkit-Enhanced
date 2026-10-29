import importlib.util
import pathlib
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
class ReleaseGateTests(unittest.TestCase):
    def test_missing_attestations_rejected(self):
        m=load('tools/production_gate.py','release_gate');self.assertIn('linux_native',m.check({}))
    def test_claim_only_not_certification(self):
        m=load('tools/production_gate.py','release_gate');self.assertEqual(len(m.check({'linux_native':{'result':'pass'}})),7)
    def test_probe_module_import(self):
        self.assertTrue(callable(load('tools/containment_probe.py','probe').probe))
if __name__=='__main__':unittest.main()
