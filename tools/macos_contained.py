#!/usr/bin/env python3
"""Fail-closed macOS sandbox launcher: only supported when sandbox-exec works.
Apple deprecated sandbox-exec; this is a restricted compatibility option, NOT
an assertion of Apple's supported security boundary. Use a networkless VM for high assurance.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROFILE = '''(version 1)
(deny default)
(allow file-read*)
(allow process-exec (subpath "/usr") (subpath "/bin") (subpath "/opt/homebrew") (subpath "/Library/Frameworks"))
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)  ; required by some Python/macOS runtime services
(allow ipc-posix-shm)
(allow file-write* (subpath "{output}"))
(allow file-write* (subpath "{temporary}"))
(deny network*)
'''

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, help='Existing private output directory')
    p.add_argument('--probe-only', action='store_true')
    a, scan_args = p.parse_known_args(argv)
    # Refuse elevated execution; avoid giving the sandbox unnecessary privilege.
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        p.error('root execution forbidden')
    if sys.platform != 'darwin' or not shutil.which('sandbox-exec'):
        p.error('macOS sandbox-exec unavailable: refusing to launch; use disconnected VM')
    output = Path(a.output).resolve(strict=True)
    if not output.is_dir() or output.is_symlink() or (output.stat().st_mode & 0o077):
        p.error('output must be a private, non-symlink directory (chmod 700)')
    if any(x in scan_args for x in ('--update', '--latest','--collect-android','--allow-external-collector')):
        p.error('online updates and external collectors refused')
    if scan_args and scan_args[0] == '--': scan_args = scan_args[1:]
    with tempfile.TemporaryDirectory(prefix='zb-sandbox-', dir=output) as temp:
        profile = Path(temp) / 'profile.sb'
        profile.write_text(PROFILE.format(output=str(output).replace('\\','\\\\').replace('"','\\"'),temporary=temp), encoding='utf8')
        profile.chmod(0o600)
        prefix = ['sandbox-exec','-f',str(profile)]
        probe = subprocess.run(prefix + [sys.executable,'-X','utf8', str(ROOT/'tools'/'containment_probe.py'),'--mode','strict'], timeout=15)
        if probe.returncode:
            print('sandbox failed containment probe; refusing scanner launch',file=sys.stderr)
            return 125
        if a.probe_only: return 0
        env = {**os.environ,'TMPDIR':temp,'TMP':temp,'TEMP':temp}
        return subprocess.run(prefix + [sys.executable,'-X','utf8',str(ROOT/'scan'/'zero-breach-toolkit.py'), '--no-feeds'] + scan_args,env=env,cwd=ROOT,timeout=1800).returncode

if __name__ == '__main__': raise SystemExit(main())
