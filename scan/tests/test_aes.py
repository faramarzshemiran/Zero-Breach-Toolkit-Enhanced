"""Plain-Python AES (zbtriage/aes.py) against the published standard vectors.

FIPS-197 Appendix C (single-block AES-128/192/256) and NIST SP 800-38A F.2.5/F.2.6
(CBC-AES256). If these pass, the implementation is the standard one.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import aes  # noqa: E402

H = bytes.fromhex


class TestSbox(unittest.TestCase):
    def test_known_entries(self):
        self.assertEqual((aes.SBOX[0x00], aes.SBOX[0x01], aes.SBOX[0x53], aes.SBOX[0xFF]),
                         (0x63, 0x7C, 0xED, 0x16))
        self.assertEqual(sorted(aes.SBOX), list(range(256)))
        self.assertTrue(all(aes.INV_SBOX[aes.SBOX[i]] == i for i in range(256)))


class TestFips197(unittest.TestCase):
    PLAIN = H("00112233445566778899aabbccddeeff")
    CASES = [
        (H("000102030405060708090a0b0c0d0e0f"), H("69c4e0d86a7b0430d8cdb78070b4c55a")),
        (H("000102030405060708090a0b0c0d0e0f1011121314151617"),
         H("dda97ca4864cdfe06eaf70a0ec0d7191")),
        (H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
         H("8ea2b7ca516745bfeafc49904b496089")),
    ]

    def test_single_block_both_ways(self):
        for key, cipher in self.CASES:
            with self.subTest(bits=len(key) * 8):
                rks = aes._aes_round_keys(key)
                self.assertEqual(aes._aes_encrypt_block(self.PLAIN, rks), cipher)
                self.assertEqual(aes._aes_decrypt_block(cipher, rks), self.PLAIN)


class TestSp80038aCbc(unittest.TestCase):
    KEY = H("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    IV = H("000102030405060708090a0b0c0d0e0f")
    PLAIN = H("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
              "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")
    CIPHER = H("f58c4c04d6e5f1ba779eabfb5f7bfbd6" "9cfc4e967edb808d679f777bc6702c7d"
               "39f23369a9d9bacfa530e26304231461" "b2eb05e2c39be9fcda6c19078c6a9d1b")

    def test_cbc_aes256(self):
        self.assertEqual(aes.aes_cbc_decrypt(self.KEY, self.IV, self.CIPHER, unpad=False),
                         self.PLAIN)
        self.assertEqual(aes.aes_cbc_encrypt(self.KEY, self.IV, self.PLAIN, pad=False),
                         self.CIPHER)

    def test_padding_round_trip_and_wrong_key(self):
        data = b"text of any length, incl. not a multiple of 16"
        enc = aes.aes_cbc_encrypt(self.KEY, self.IV, data)
        self.assertEqual(aes.aes_cbc_decrypt(self.KEY, self.IV, enc), data)
        wrong = bytes(32)
        failures = 0
        try:
            aes.aes_cbc_decrypt(wrong, self.IV, enc)
        except aes.AesPaddingError:
            failures += 1
        self.assertEqual(failures, 1)

    def test_rejects_bad_shapes(self):
        with self.assertRaises(ValueError):
            aes.aes_cbc_decrypt(self.KEY, self.IV, b"short")
        with self.assertRaises(ValueError):
            aes._aes_round_keys(b"x" * 20)


if __name__ == "__main__":
    unittest.main()
