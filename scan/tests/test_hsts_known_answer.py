"""Chromium's TransportSecurity file keys each host by base64(SHA-256) of the
host in DNS wire form (length-prefixed labels and a final zero byte), not of
the plain host name. These values were read from real Chrome and Edge
TransportSecurity files, so the check does not depend on our own encoder."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.modules.browser import _hsts_fingerprint

# Entries observed in real browser profiles for these public hosts.
OBSERVED = {
    "github.com": "bVzOnu6xyelN8iVLDSbFjyZVgXrXDyLSokjnq2hdUFs=",
}


def test_fingerprint_matches_real_browser_entries():
    for host, stored in OBSERVED.items():
        assert _hsts_fingerprint(host) == stored


def test_case_and_trailing_dot_do_not_change_the_fingerprint():
    assert _hsts_fingerprint("GitHub.com.") == OBSERVED["github.com"]
