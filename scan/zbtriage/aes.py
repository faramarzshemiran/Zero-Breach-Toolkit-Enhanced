"""AES (FIPS-197) and CBC mode in plain Python - for reading a person's own
encrypted backup, so the tool needs no extra package.

Used to decrypt an Android SMS backup (kilobytes to a few megabytes); plain Python
is far too slow for multi-gigabyte iPhone backups, which use an optional library
instead. This reads a selected local backup with the owner's supplied password;
it does not provide an encryption scheme for protecting new data. Correctness
is checked against NIST FIPS-197 and SP 800-38A vectors in tests/test_aes.py.
Python does not guarantee secure erasure of key or plaintext memory.

The S-box is computed from its definition (multiplicative inverse in GF(2^8)
followed by the affine transform), not typed in, so a single mistyped byte cannot
silently corrupt it; the tests also spot-check known entries.
"""


def _aes_rotl8(x, shift):
    return ((x << shift) | (x >> (8 - shift))) & 0xFF


def _aes_make_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        # p walks the multiplicative group (multiply by 3); q = p's inverse.
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ _aes_rotl8(q, 1) ^ _aes_rotl8(q, 2) ^ _aes_rotl8(q, 3) ^ _aes_rotl8(q, 4)
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


SBOX, INV_SBOX = _aes_make_sbox()


def _aes_gmul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1
        b >>= 1
    return out


_AES_MUL = {n: [_aes_gmul(i, n) for i in range(256)] for n in (2, 3, 9, 11, 13, 14)}
_AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _aes_round_keys(key):
    nk = len(key) // 4
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= _AES_RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def _aes_decrypt_block(block, rks):
    m9, m11, m13, m14 = _AES_MUL[9], _AES_MUL[11], _AES_MUL[13], _AES_MUL[14]
    nr = len(rks) - 1
    s = [b ^ k for b, k in zip(block, rks[nr])]
    for rnd in range(nr - 1, -1, -1):
        # InvShiftRows (row r moves right by r) + InvSubBytes, state is column-major
        s = [INV_SBOX[s[r + 4 * ((c - r) % 4)]] for c in range(4) for r in range(4)]
        s = [b ^ k for b, k in zip(s, rks[rnd])]
        if rnd == 0:
            break
        out = []
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c:4 * c + 4]
            out += [m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3],
                    m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3],
                    m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3],
                    m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]]
        s = out
    return bytes(s)


def _aes_encrypt_block(block, rks):
    """Used by the tests to build encrypted fixtures; the scanner only decrypts."""
    m2, m3 = _AES_MUL[2], _AES_MUL[3]
    nr = len(rks) - 1
    s = [b ^ k for b, k in zip(block, rks[0])]
    for rnd in range(1, nr + 1):
        s = [SBOX[s[r + 4 * ((c + r) % 4)]] for c in range(4) for r in range(4)]
        if rnd != nr:
            out = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                out += [m2[a0] ^ m3[a1] ^ a2 ^ a3, a0 ^ m2[a1] ^ m3[a2] ^ a3,
                        a0 ^ a1 ^ m2[a2] ^ m3[a3], m3[a0] ^ a1 ^ a2 ^ m2[a3]]
            s = out
        s = [b ^ k for b, k in zip(s, rks[rnd])]
    return bytes(s)


class AesPaddingError(ValueError):
    """The decrypted data does not end in valid PKCS#7 padding - almost always a
    wrong password."""


def aes_cbc_decrypt(key, iv, data, unpad=True):
    if len(iv) != 16 or len(data) % 16:
        raise ValueError("CBC data must be whole 16-byte blocks with a 16-byte IV")
    rks = _aes_round_keys(bytes(key))
    out = bytearray()
    prev = bytes(iv)
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        plain = _aes_decrypt_block(block, rks)
        out += bytes(a ^ b for a, b in zip(plain, prev))
        prev = block
    if unpad:
        n = out[-1] if out else 0
        if not 1 <= n <= 16 or out[-n:] != bytes([n]) * n:
            raise AesPaddingError("bad padding")
        del out[-n:]
    return bytes(out)


def aes_cbc_encrypt(key, iv, data, pad=True):
    if pad:
        n = 16 - len(data) % 16
        data = bytes(data) + bytes([n]) * n
    if len(iv) != 16 or len(data) % 16:
        raise ValueError("CBC data must be whole 16-byte blocks with a 16-byte IV")
    rks = _aes_round_keys(bytes(key))
    out = bytearray()
    prev = bytes(iv)
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = _aes_encrypt_block(block, rks)
        out += prev
    return bytes(out)
