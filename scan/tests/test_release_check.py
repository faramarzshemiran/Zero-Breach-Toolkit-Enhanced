"""Regressions for false-green failures in the offline release gate itself."""
import importlib.util
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release_gate", ROOT / "tools/release_check.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class TestWebDownloadChecksum(unittest.TestCase):
    DIGEST = "a" * 64

    def panel(self, displayed=None, copied=None):
        return ('<div id="verify-download"><div class="ea-copy"><code>{}</code>'
                '<button data-copy="{}">Copy SHA-256</button></div></div>').format(
                    displayed or self.DIGEST, copied or self.DIGEST)

    def test_actual_code_and_copy_value_match(self):
        gate.check_web_checksum(self.panel(), self.DIGEST)

    def test_correct_hash_in_comment_does_not_mask_wrong_display(self):
        html = self.panel(displayed="b" * 64) + "<!-- " + self.DIGEST + " -->"
        with self.assertRaisesRegex(RuntimeError, "displayed/copied"):
            gate.check_web_checksum(html, self.DIGEST)

    def test_correct_display_does_not_mask_wrong_copy_value(self):
        with self.assertRaisesRegex(RuntimeError, "displayed/copied"):
            gate.check_web_checksum(self.panel(copied="b" * 64), self.DIGEST)


class TestRequiredReleaseInputs(unittest.TestCase):
    def test_required_website_cannot_be_silently_skipped(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(gate, "ROOT", Path(temp)):
            with self.assertRaisesRegex(RuntimeError, "Website verification required"):
                gate.release_web_directory(None, required=True)
            self.assertIsNone(gate.release_web_directory(None))
            supplied = Path(temp) / "separate-site"
            self.assertEqual(gate.release_web_directory(supplied, required=True), supplied)

    def test_saved_download_must_match_bytes_without_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            downloaded = Path(temp) / "download.py"
            content = b"raise RuntimeError('must never execute a download')\n"
            downloaded.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            gate.check_downloaded_scanner(downloaded, digest)
            downloaded.write_bytes(content + b"# different build\n")
            with self.assertRaisesRegex(RuntimeError, "Downloaded scanner differs"):
                gate.check_downloaded_scanner(downloaded, digest)

    def test_required_encryption_cannot_be_silently_skipped(self):
        with patch.object(gate.importlib.util, "find_spec", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Encrypted-backup coverage requires"):
                gate.check_backup_dependency()

    def test_required_encryption_checks_the_pinned_version(self):
        with patch.object(gate.importlib.util, "find_spec", return_value=object()), \
                patch("importlib.metadata.version", return_value="0.0.0"):
            with self.assertRaisesRegex(RuntimeError, "differs from requirements-backups"):
                gate.check_backup_dependency()


class TestCaughtNetworkAttempt(unittest.TestCase):
    def test_scanner_cannot_hide_an_attempt_by_catching_guard_exception(self):
        with tempfile.TemporaryDirectory(prefix="zb_gate_regression_") as tmp:
            root = Path(tmp)
            candidate = root / "candidate.py"
            subprocess.run([sys.executable, "-B", str(ROOT / "build/bundle.py"),
                            str(ROOT), str(candidate)], check=True, capture_output=True)
            source = candidate.read_text(encoding="utf-8")
            needle = "def _pattern_engine():"
            self.assertIn(needle, source)
            # no_network blocks this before any real resolution; the pattern
            # module catches it and would normally just report UNKNOWN.
            source = source.replace(needle, needle + '\n    __import__("socket").'
                                    'gethostbyname("release-fixture.invalid")')
            candidate.write_text(source, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-B", str(ROOT / "tools/release_fixture.py"),
                 "bundle", "patterns", str(root / "fixture"), str(candidate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(b"blocked external activity occurred", proc.stderr)


if __name__ == "__main__":
    unittest.main()
