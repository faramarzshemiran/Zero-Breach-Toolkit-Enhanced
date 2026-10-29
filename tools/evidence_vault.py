#!/usr/bin/env python3
"""Explicitly encrypt/decrypt an evidence file with AES-256-GCM and scrypt.
Passphrases are prompted, never accepted as process arguments. This helper is not
transparent full-disk encryption: plaintext originals remain until securely managed.
"""
import argparse
import getpass
import os
import pathlib
import stat
import sys
import tempfile

MAGIC = b'ZBVAULT1'
MAX_INPUT = 2 * 1024 * 1024 * 1024

def _cryptography():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError as exc:
        raise RuntimeError('install reviewed cryptography dependency to use evidence vault') from exc
    return AESGCM, Scrypt

def transform(source, destination, password, decrypt=False):
    AESGCM, Scrypt = _cryptography()
    source, destination = pathlib.Path(source), pathlib.Path(destination)
    if source.is_symlink() or not source.is_file() or destination.is_symlink():
        raise ValueError('input must be a regular file; symlinks are refused')
    if source.resolve() == destination.resolve():
        raise ValueError('source and destination cannot coincide')
    if len(password) < 16:
        raise ValueError('passphrase must contain at least 16 characters')
    if source.stat().st_size > MAX_INPUT:
        raise ValueError('file exceeds bounded in-memory vault limit')
    parent = destination.parent.resolve(strict=True)
    if destination.exists():
        raise FileExistsError('destination must not already exist')
    raw = source.read_bytes()
    if decrypt:
        if len(raw) < len(MAGIC) + 16 + 12 + 16 or not raw.startswith(MAGIC):
            raise ValueError('invalid encrypted evidence format')
        salt, nonce, content = raw[8:24], raw[24:36], raw[36:]
    else:
        salt, nonce, content = os.urandom(16), os.urandom(12), raw
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode('utf-8'))
    result = AESGCM(key).decrypt(nonce, content, MAGIC) if decrypt else MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, content, MAGIC)
    fd, tmp = tempfile.mkstemp(prefix='.zbvault-', dir=parent)
    try:
        if os.name == 'posix':
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, 'wb') as stream:
            fd = -1
            stream.write(result)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic no-clobber creation via hard-link, not replace.
        os.link(tmp, destination)
    finally:
        if fd >= 0:
            os.close(fd)
        pathlib.Path(tmp).unlink(missing_ok=True)

def encrypt_bytes(plaintext, destination, password):
    """Atomic, no-clobber, authenticated evidence write without intermediate plaintext."""
    AESGCM, Scrypt = _cryptography()
    destination = pathlib.Path(destination)
    if len(password) < 16:
        raise ValueError('passphrase must contain at least 16 characters')
    if len(plaintext) > MAX_INPUT:
        raise ValueError('evidence exceeds bounded encryption limit')
    if destination.is_symlink() or destination.exists():
        raise FileExistsError('encrypted destination already exists')
    parent = destination.parent.resolve(strict=True)
    if os.name == 'posix' and parent.stat().st_mode & 0o077:
        raise PermissionError('encrypted evidence directory must be private (chmod 700)')
    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode('utf-8'))
    encrypted = MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, bytes(plaintext), MAGIC)
    fd, tmp = tempfile.mkstemp(prefix='.zbvault-', dir=parent)
    try:
        if os.name == 'posix': os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            fd = -1
            stream.write(encrypted)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(tmp, destination)
    finally:
        if fd >= 0: os.close(fd)
        pathlib.Path(tmp).unlink(missing_ok=True)

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('encrypt', 'decrypt'))
    p.add_argument('source')
    p.add_argument('destination')
    a = p.parse_args(argv)
    phrase = getpass.getpass('Evidence passphrase: ')
    if a.operation == 'encrypt':
        confirmation = getpass.getpass('Confirm passphrase: ')
        if phrase != confirmation:
            p.error('passphrases differ')
    try:
        transform(a.source, a.destination, phrase, a.operation == 'decrypt')
    except (ValueError, OSError, RuntimeError) as exc:
        p.error(str(exc))
    print('Evidence file processed. Review retention of plaintext originals and backups.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
