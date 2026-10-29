"""Hosts hidden by URL escapes, IPv6 written in other forms, and the matcher's
worst case on a crafted token.

Ad-click and redirect URLs carry their destination percent-encoded or
JS-escaped, so the letters of the escape sit against the host name and the
boundary rule (rightly) refuses it. The decoded copy of the text is searched
as well. IPv6 addresses have many equivalent spellings; they are compared in
canonical form.
"""

from __future__ import annotations

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.iocs import TYPE_DOMAIN, TYPE_IP, Indicator, IocSet  # noqa: E402


def make(*values):
    inds = [Indicator(v, "infrastructure-ip" if t == TYPE_IP else "cc", "primary", t)
            for v, t in values]
    return IocSet(sorted(inds, key=lambda i: i.value), "test", None)


DOMS = make(("fearevolve.com", TYPE_DOMAIN), ("mtrtb.com", TYPE_DOMAIN),
            ("noas.mtrtb.com", TYPE_DOMAIN), ("controlium.net", TYPE_DOMAIN))


def found(iocs, text):
    return [i.value for i in iocs.search(text.lower())]


def found_bytes(iocs, data):
    return [i.value for i in iocs.search_bytes(data.lower())]


class TestEscapedHosts(unittest.TestCase):
    def test_percent_encoded_url(self):
        self.assertEqual(found(DOMS, "click?u=https%3A%2F%2Ffearevolve.com%2Fx"),
                         ["fearevolve.com"])

    def test_double_encoded_url(self):
        self.assertEqual(found(DOMS, "r=https%253A%252F%252Ffearevolve.com%252F"),
                         ["fearevolve.com"])

    def test_js_escaped_slashes(self):
        self.assertEqual(found(DOMS, '{"u":"https:\\/\\/fearevolve.com\\/a"}'),
                         ["fearevolve.com"])

    def test_js_hex_and_unicode_escapes(self):
        self.assertEqual(found(DOMS, "a\\x2f\\x2ffearevolve.com"), ["fearevolve.com"])
        self.assertEqual(found(DOMS, "a\\u002f\\u002ffearevolve.com"), ["fearevolve.com"])

    def test_escaped_subdomain_reports_the_specific_endpoint(self):
        # Without decoding only the parent matched (through the after-dot start).
        self.assertEqual(found(DOMS, "u=https%3a%2f%2fnoas.mtrtb.com%2fx"),
                         ["noas.mtrtb.com"])

    def test_parent_kept_when_it_also_stands_alone(self):
        self.assertEqual(sorted(found(DOMS, "%2f%2fnoas.mtrtb.com and mtrtb.com")),
                         ["mtrtb.com", "noas.mtrtb.com"])

    def test_bytes_narrow_and_utf16(self):
        blob = b"\x01\x02u=https%3a%2f%2ffearevolve.com%2f\x00\x00"
        self.assertEqual(found_bytes(DOMS, blob), ["fearevolve.com"])
        wide = "u=https%3a%2f%2ffearevolve.com%2f".encode("utf-16-le")
        self.assertEqual(found_bytes(DOMS, b"\x00\x05" + wide), ["fearevolve.com"])

    def test_escape_does_not_invent_a_longer_name(self):
        # %41 decodes to a letter that continues the label: no match from the
        # decoded copy, and the original's genuine match is kept.
        self.assertEqual(found(DOMS, "controlium.net%41"), ["controlium.net"])
        self.assertEqual(found(DOMS, "notcontrolium.net%2f"), [])

    def test_plain_text_unchanged(self):
        self.assertEqual(found(DOMS, "https://fearevolve.com/x"), ["fearevolve.com"])
        self.assertEqual(found(DOMS, "100% sure, nothing here"), [])


IP6 = make(("2a02:db8::1", TYPE_IP), ("controlium.net", TYPE_DOMAIN))


class TestIpv6Forms(unittest.TestCase):
    def test_equivalent_spellings_match(self):
        for text in ("conn 2a02:db8:0:0::1 ok", "2A02:0DB8:0000:0000:0000:0000:0000:0001",
                     "[2a02:db8::0:1]:443", "2a02:db8:0:0:0:0:0:1"):
            self.assertEqual(found(IP6, text), ["2a02:db8::1"], text)

    def test_bytes_and_utf16(self):
        self.assertEqual(found_bytes(IP6, b"x 2a02:db8:0::1 y"), ["2a02:db8::1"])
        self.assertEqual(found_bytes(IP6, "x 2a02:db8:0::1 y".encode("utf-16-le")),
                         ["2a02:db8::1"])

    def test_not_inside_a_longer_address(self):
        self.assertEqual(found(IP6, "2a02:db8::1:5"), [])
        self.assertEqual(found(IP6, "ff2a02:db8:0::1"), [])
        self.assertEqual(found(IP6, "12:34:56"), [])


class TestCraftedTokenIsLinear(unittest.TestCase):
    def test_many_dots_finish_quickly(self):
        token = "a.com" + "..com" * 6000
        started = time.perf_counter()
        DOMS.search(token)
        DOMS.search_bytes(token.encode("ascii"))
        self.assertLess(time.perf_counter() - started, 2.0)


if __name__ == "__main__":
    unittest.main()
