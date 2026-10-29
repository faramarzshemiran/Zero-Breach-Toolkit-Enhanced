#!/usr/bin/env python3
"""Explicit ONLINE indicator refresh in a dedicated process; pinned sources only."""
import argparse
import pathlib
import subprocess
import sys
ROOT = pathlib.Path(__file__).resolve().parents[1]

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--indicator-cache', help='private per-user indicator cache')
    args = parser.parse_args(argv)
    command = [sys.executable, '-X', 'utf8', str(ROOT/'scan/zero-breach-toolkit.py'), '--update', '--no-banner']
    if args.indicator_cache:
        command += ['--indicator-cache', args.indicator_cache]
    try:
        return subprocess.run(command, cwd=str(ROOT), check=False, timeout=900).returncode
    except subprocess.TimeoutExpired:
        return 124
if __name__ == '__main__':
    raise SystemExit(main())
