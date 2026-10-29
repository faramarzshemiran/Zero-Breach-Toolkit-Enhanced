"""Regression tests for explicit trust-boundary controls (no real network/device)."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from argparse import Namespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from zbtriage.security_policy import RunPolicy, SecurityPolicyError, validate_requested_operation
from zbtriage.cli import main, _parse
from zbtriage.report import write_json


class SecurityPolicyTests(unittest.TestCase):
    def test_offline_defaults(self):
        policy = validate_requested_operation(Namespace())
        self.assertEqual((policy.mode, policy.network, policy.external_execution), ("offline", "deny", False))

    def test_offline_cannot_enable_network_or_exec(self):
        for policy in (RunPolicy("offline", "update-only"), RunPolicy("offline", "deny", True)):
            with self.assertRaises(SecurityPolicyError):
                policy.validate()

    def test_collector_blocked_by_default(self):
        with self.assertRaises(SecurityPolicyError):
            validate_requested_operation(Namespace(collect_android="/tmp/example", allow_external_collector=False))

    def test_high_assurance_refuses_false_claims(self):
        with self.assertRaisesRegex(SecurityPolicyError, "refuses"):
            validate_requested_operation(Namespace(high_assurance=True))

    def test_update_is_explicit_distinct_mode(self):
        p = validate_requested_operation(Namespace(update=True))
        self.assertEqual((p.mode, p.network), ("update", "update-only"))

    def test_unsupported_collector_cannot_execute(self):
        with patch("zbtriage.phoneguide.collect_android", side_effect=AssertionError("must not execute")):
            self.assertEqual(main(["--collect-android", "/tmp/zb_test_never_create", "--no-banner", "--no-menu"]), 1)

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions only')
    def test_report_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'report.json')
            write_json({'status': 'test'}, path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_reject_collector_unlock_without_collector(self):
        with self.assertRaises(SystemExit):
            _parse(['--allow-external-collector'])


if __name__ == '__main__':
    unittest.main()
