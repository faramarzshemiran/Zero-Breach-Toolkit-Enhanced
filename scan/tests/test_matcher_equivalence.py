"""The fast (tokenising) matcher must give EXACTLY the results of the original
per-indicator loop, which is kept as IocSet._search_reference /
_search_bytes_reference for this purpose.

Precision is the whole job: the boundary rules are what stop notcontrolium.net
from matching controlium.net. A faster matcher that drifted would be worse than
a slow one, so this test generates thousands of adversarial haystacks around
real indicators - subdomains, trailing dots, '_' and '-' at the edges, IPs inside
longer numbers, UTF-16 text at even and odd byte offsets, mixed encodings - and
requires identical answers, in identical order, every time.
"""

from __future__ import annotations

import glob
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.iocs import (TYPE_DOMAIN, TYPE_IP, Indicator, IocSet,  # noqa: E402
                           load_any, merge)

CRAFTED = [
    ("controlium.net", TYPE_DOMAIN), ("noas.powerium.net", TYPE_DOMAIN),
    ("powerium.net", TYPE_DOMAIN), ("a.b.c.example", TYPE_DOMAIN),
    ("b.c.example", TYPE_DOMAIN), ("xn--bcher-kva.example", TYPE_DOMAIN),
    ("x-y.example", TYPE_DOMAIN), ("long-label-name-here.example.org", TYPE_DOMAIN),
    ("52.174.65.77", TYPE_IP), ("5.6.7.8", TYPE_IP), ("2a02:db8::1", TYPE_IP),
]
PREFIXES = ["", "", "", "www.", "a.", "x", "-", "_", ".", "..", "1", "é", "/", "=",
            "https://", "a-", "\x00", " ", "%2f%2f", "%252f", "https:\\/\\/",
            "\\x2f", "%41", "%2e", "u=https%3a%2f%2f"]
SUFFIXES = ["", "", "", ".", ".x", "x", "-", "_", "..", "/", ":443", ".com", "1",
            ".1", "é", "=", "\x00", " ", "./", ".-", "%2f", "%2e", "%41", "\\/", ":0"]
JUNK = ["the", "cookie", "net", "example", "org", "com", "1.2", "52.174.65.7",
        "152.174.65.771", "notcontrolium.net", "controlium.network", "a.b",
        "...", "-.-", "_x_", "2a02", "db8", "::", "é", "\x00\x00",
        "2a02:db8:0:0::1", "2a02:0db8::0001", "100%", "%zz", "\\u002f"]


def crafted_set():
    inds = [Indicator(v, "infrastructure" if t == TYPE_DOMAIN else "infrastructure-ip",
                      "primary", t) for v, t in CRAFTED]
    return IocSet(sorted(inds, key=lambda i: i.value), "crafted", None)


def text_case(rng, values):
    parts = []
    for _ in range(rng.randint(1, 12)):
        if rng.random() < 0.55:
            parts.append(rng.choice(PREFIXES) + rng.choice(values) + rng.choice(SUFFIXES))
        else:
            parts.append(rng.choice(JUNK))
        parts.append(rng.choice(["", " ", ".", "/", "\x00", "-", "_", "=", "é", "\n"]))
    return "".join(parts)


def bytes_case(rng, values):
    out = bytearray()
    if rng.random() < 0.3:
        out += b"\x01"                       # shift what follows to an odd offset
    for _ in range(rng.randint(1, 8)):
        seg = text_case(rng, values)
        if rng.random() < 0.5:
            out += seg.encode("utf-16-le")
        else:
            out += seg.encode("utf-8")
        if rng.random() < 0.3:
            out += bytes([rng.randint(0, 255)])
    return bytes(out).lower()


class TestEquivalence(unittest.TestCase):
    def check(self, iocs, values, seed, n):
        rng = random.Random(seed)
        for k in range(n):
            text = text_case(rng, values).lower()
            new = [i.value for i in iocs.search(text)]
            ref = [i.value for i in iocs._search_reference(text)]
            self.assertEqual(new, ref, "str case %d: %r" % (k, text))
            data = bytes_case(rng, values)
            new_b = [i.value for i in iocs.search_bytes(data)]
            ref_b = [i.value for i in iocs._search_bytes_reference(data)]
            self.assertEqual(new_b, ref_b, "bytes case %d: %r" % (k, data))

    def test_crafted_indicators_adversarial_contexts(self):
        iocs = crafted_set()
        self.check(iocs, [v for v, _ in CRAFTED], seed=20261025, n=4000)

    def test_matches_actually_occur(self):
        # Guard against a vacuous pass: the generator must produce real hits.
        iocs = crafted_set()
        rng = random.Random(7)
        hits = sum(len(iocs.search(text_case(rng, [v for v, _ in CRAFTED]).lower()))
                   for _ in range(300))
        self.assertGreater(hits, 100)

    def test_real_published_indicator_sets(self):
        d = os.path.join(os.environ.get("LOCALAPPDATA", ""), "mvt", "mvt", "indicators")
        paths = sorted(glob.glob(os.path.join(d, "*.stix2")))
        if not paths:
            self.skipTest("published STIX bundles not cached on this machine")
        iocs = merge([load_any(p, allow_empty=True) for p in paths])
        rng = random.Random(1)
        net = [i.value for i in iocs.indicators if i.type in (TYPE_DOMAIN, TYPE_IP)]
        sample = rng.sample(net, 300) + [v for v, _ in CRAFTED]
        self.check(iocs, sample, seed=99, n=600)


if __name__ == "__main__":
    unittest.main()


class TestIpv4SinglePass(unittest.TestCase):
    """The one-pass IPv4 search must agree with the per-indicator
    loop on overlapping and edge-of-number cases, in str, narrow and wide text."""

    CASES = ["5.6.7.8.9", "15.6.7.8", "5.6.7.89", "5.6.7.8x", "x5.6.7.8", "5.6.7.8.",
             ".5.6.7.8", "4.5.6.7.8", "05.6.7.8", "5.6.7.8,4.5.6.7", "5.6.7.8:443",
             "http://5.6.7.8/a", "1.2.3.4.5.6.7.8", "5..6.7.8", "a-5.6.7.8-b"]

    def test_same_as_reference(self):
        inds = [Indicator(v, "infrastructure-ip", "primary", TYPE_IP, "t")
                for v in ("5.6.7.8", "4.5.6.7", "2.3.4.5", "6.7.8.9")]
        s = IocSet(inds, "t.txt", None)
        for case in self.CASES:
            with self.subTest(case=case):
                text = "pre " + case + " post"
                self.assertEqual([i.value for i in s.search(text)],
                                 [i.value for i in s._search_reference(text)])
                for blob in (text.encode(), text.encode("utf-16-le")):
                    self.assertEqual([i.value for i in s.search_bytes(blob)],
                                     [i.value for i in s._search_bytes_reference(blob)])


class TestDomainTokenShortcuts(unittest.TestCase):
    """The dotted-token regex and the restricted start/end positions
    must agree with the per-indicator loop, in str, narrow and wide text."""

    CASES = ["evil.example.com", "evil.example.com.", "evil.example.com..", "evil.example.com._x",
             "evil.example.com.-x", "evil.example.com.x", "evil.example.com_x", "evil.example.com-x",
             "xevil.example.com", "x.evil.example.com", "-evil.example.com", "_evil.example.com",
             ".evil.example.com", "evil.example.com.evil.example.com", "evil..example.com",
             "a.b.c.d.e.f.g.evil.example.com", "evil.example.comm", "example.com",
             "noas.powerium.net", "qa-noas.powerium.net.", "powerium.net/x", "1.2.3"]

    def test_same_as_reference(self):
        inds = [Indicator(v, "infrastructure", "primary", TYPE_DOMAIN, "t")
                for v in ("evil.example.com", "example.com", "powerium.net",
                          "noas.powerium.net", "g.evil.example.com")]
        s = IocSet(inds, "t.txt", None)
        for case in self.CASES:
            for text in (case, "see " + case + " now", "url=https://" + case + "/p"):
                with self.subTest(text=text):
                    self.assertEqual([i.value for i in s.search(text)],
                                     [i.value for i in s._search_reference(text)])
                    for blob in (text.encode(), text.encode("utf-16-le")):
                        self.assertEqual(
                            [i.value for i in s.search_bytes(blob)],
                            [i.value for i in s._search_bytes_reference(blob)])


class TestHostMatchWalk(unittest.TestCase):
    """browser._host_matches walks a host's parents instead of comparing it with
    every domain; it must pick exactly what the old loop picked."""

    @staticmethod
    def old(host, s):
        host = host.lower().strip(".")
        ind = s.lookup(host)
        if ind is not None:
            return ind
        best = None
        for c in s.indicators:
            if c.type == "domain" and host.endswith("." + c.value):
                if best is None or len(c.value) > len(best.value):
                    best = c
        return best

    def test_same_choice_as_the_old_loop(self):
        from zbtriage.modules import browser
        inds = [Indicator(v, "infrastructure", "primary", TYPE_DOMAIN, "t")
                for v in ("powerium.net", "noas.powerium.net", "qa-noas.powerium.net",
                          "example.com", "deep.a.example.com")]
        inds.append(Indicator("5.6.7.8", "infrastructure-ip", "primary", TYPE_IP, "t"))
        s = IocSet(inds, "t.txt", None)
        hosts = ["powerium.net", "x.powerium.net", "noas.powerium.net", "a.noas.powerium.net",
                 "qa-noas.powerium.net", "b.qa-noas.powerium.net", "notpowerium.net",
                 "powerium.net.", "X.NOAS.POWERIUM.NET", "a.example.com", "x.deep.a.example.com",
                 "deep.a.example.com.evil", "5.6.7.8", "a.5.6.7.8", "com", "", "."]
        for host in hosts:
            with self.subTest(host=host):
                old, new = self.old(host, s), browser._host_matches(host, s)
                self.assertEqual(old.value if old else None, new.value if new else None)
