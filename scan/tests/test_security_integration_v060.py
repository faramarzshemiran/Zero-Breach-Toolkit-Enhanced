import importlib.util, pathlib, sys, tempfile, unittest, os, json
ROOT=pathlib.Path(__file__).resolve().parents[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
vault=load('vault_integrated',ROOT/'tools/evidence_vault.py')
containers=load('container_run_integrated',ROOT/'tools/container_run.py')
attest=load('platform_attest_integrated',ROOT/'tools/platform_attest.py')
class IntegrationTests(unittest.TestCase):
 def test_container_rejects_mutable_image(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError):containers.build('podman','latest',d,d,[])
 def test_container_forbids_network(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises((ValueError,RuntimeError)):containers.build('podman','repo@sha256:'+'f'*64,d,d,['--update'])
 def test_attestation_denies_empty(self):self.assertFalse(attest.verify({}))
 def test_encrypted_output_no_plaintext(self):
  try:import cryptography
  except ImportError:self.skipTest('cryptography not installed')
  with tempfile.TemporaryDirectory() as d:
   os.chmod(d,0o700);path=pathlib.Path(d)/'case.zbe';vault.encrypt_bytes(b'TOP-SECRET-CASE',path,'long-test-passphrase!')
   self.assertNotIn(b'TOP-SECRET-CASE',path.read_bytes())
   self.assertTrue(path.read_bytes().startswith(vault.MAGIC))
   with self.assertRaises(FileExistsError):vault.encrypt_bytes(b'x',path,'long-test-passphrase!')
 def test_cli_accepts_integrated_encryption(self):
  sys.path.insert(0,str(ROOT/'scan'))
  from zbtriage.cli import _parse
  a=_parse(['--no-menu','--encrypted-json','private/report.zbe'])
  self.assertEqual(a.encrypted_json,'private/report.zbe')
 def test_cli_refuses_plaintext_combination(self):
  sys.path.insert(0,str(ROOT/'scan'))
  from zbtriage.cli import _parse
  with self.assertRaises(SystemExit):_parse(['--encrypted-json','case.zbe','--json','case.json'])
 def test_original_utf8_launcher_still_exists(self):
  self.assertTrue((ROOT/'scan/zero-breach-toolkit.py').is_file())
if __name__=='__main__':unittest.main()
