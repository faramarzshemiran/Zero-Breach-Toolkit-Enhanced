"""A SHA-1 certificate fingerprint cannot be compared with a SHA-256
certificate indicator (or the reverse): certificate coverage counts only the
digest kinds that are loaded and actually present."""
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_discovery_and_fingerprint_gaps import android_api
from test_evidence_safety import _ctx
from test_followup_fixes import bundle
from zbtriage.iocs import TYPE_APP_CERT, Indicator, IocSet
from zbtriage.modules import android
from zbtriage.result import ModuleResult

SHA256_CERT = "01" * 32
SHA1_CERT = "02" * 20


def _certificate_check(api, cert, indicators):
    ctx = _ctx()
    ctx.iocs = IocSet([Indicator(v, "infrastructure", "primary", TYPE_APP_CERT, "fixture") for v in indicators],
                      "fixture", None)
    result = ModuleResult("android") if api is android else api.ModuleResult("android")
    info = {"installed": {}, "appops": {}, "receivers": {}, "notification": set(),
            "accessibility": set(), "admins": set()}
    record = {"name": "com.example", "third_party": True,
              "files": [{"path": "/data/app/x/base.apk", "sha256": "ab" * 32, "certificate": cert}]}
    with tempfile.TemporaryDirectory() as folder:
        with open(os.path.join(folder, "packages.json"), "w", encoding="utf-8") as fh:
            json.dump([record], fh)
        api._an_packages(result, ctx, folder, info)
    return {c.name: (c.ran, c.reason) for c in result.checks}["android:app-certificates"]


@pytest.mark.parametrize("cert,indicators,covered", (
    ({"Sha256": "", "Sha1": SHA1_CERT}, (SHA256_CERT,), False),
    ({"Sha256": SHA256_CERT, "Sha1": ""}, (SHA1_CERT,), False),
    ({"Sha256": "", "Sha1": SHA1_CERT}, (SHA1_CERT,), True),
    ({"Sha256": SHA256_CERT, "Sha1": ""}, (SHA256_CERT,), True),
    ({"Sha256": SHA256_CERT, "Sha1": ""}, (SHA256_CERT, SHA1_CERT), False),
    ({"Sha256": SHA256_CERT, "Sha1": SHA1_CERT}, (SHA256_CERT, SHA1_CERT), True),
))
def test_certificate_coverage_follows_the_loaded_digests(android_api, cert, indicators, covered):
    ran, reason = _certificate_check(android_api, cert, indicators)
    assert ran is covered
    if not covered:
        assert "user-installed" in reason and ("SHA-256" in reason or "SHA-1" in reason)
