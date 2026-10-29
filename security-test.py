#!/usr/bin/env python3
"""Self-contained test harness: default excludes network/device/hardware tests."""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
p = argparse.ArgumentParser()
p.add_argument('--suite', choices=('security', 'all'), default='all')
p.add_argument('--verbose', action='store_true')
p.add_argument('--timeout', type=int, default=240)
a = p.parse_args()
cmd = [sys.executable, '-m', 'unittest', 'discover', '-s', str(ROOT / 'scan/tests'), '-p',
       'test_security*.py' if a.suite == 'security' else 'test_*.py']
if a.verbose: cmd.append('-v')
print('Running:', ' '.join(cmd), flush=True)
try:
    r = subprocess.run(cmd, cwd=ROOT, timeout=a.timeout, check=False)
except subprocess.TimeoutExpired:
    print('TIMEOUT: test suite exceeded limit', file=sys.stderr)
    raise SystemExit(124)
raise SystemExit(r.returncode)
