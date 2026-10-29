#!/usr/bin/env python3
"""Fail-closed launcher. Linux strict offline = kernel network namespace or no scan.
Never claims Windows/macOS enforcement. No third-party collectors are executed.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCAN = ROOT / "scan" / "zero-breach-toolkit.py"


def build_command(profile, scan_args, system=sys.platform, executable=sys.executable):
    if any(x in scan_args for x in ('--update', '--collect-android', '--allow-external-collector', '--latest', '--update-indicators')):
        raise ValueError('scanner profile refuses network updates, third-party collectors and latest-unpinned indicators')
    base = [executable, '-X', 'utf8', str(SCAN)]
    if profile == 'offline-strict':
        if not system.startswith('linux'):
            raise RuntimeError('strict offline sandbox only implemented on Linux; use a verified OS firewall/VM isolation and offline-standard elsewhere')
        unshare = shutil.which('unshare')
        if not unshare:
            raise RuntimeError('strict offline requires util-linux unshare')
        # CLONE_NEWNET affects subprocess children, including Powershell etc.
        return [unshare, '--net', '--'] + base + scan_args
    if profile == 'offline-standard':
        return base + ['--no-feeds'] + scan_args
    raise ValueError('unknown profile')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--profile', choices=('offline-strict', 'offline-standard'), default='offline-strict')
    ap.add_argument('--', dest='separator', action='store_true', help=argparse.SUPPRESS)
    opts, rest = ap.parse_known_args(argv)
    if rest and rest[0] == '--':
        rest = rest[1:]
    try:
        command = build_command(opts.profile, rest)
    except (ValueError, RuntimeError) as exc:
        ap.error(str(exc))
    try:
        return subprocess.run(command, cwd=str(ROOT), check=False, timeout=1800).returncode
    except subprocess.TimeoutExpired:
        print('isolated scan timed out', file=sys.stderr)
        return 124
    except OSError as exc:
        print('sandbox unavailable, refusing fallback: ' + str(exc), file=sys.stderr)
        return 125

if __name__ == '__main__':
    raise SystemExit(main())
