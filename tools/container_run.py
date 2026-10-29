#!/usr/bin/env python3
"""Containerised offline scanner. Requires a trusted locally pinned image.
Never pulls images. The user must independently assess the container runtime and image.
Target mounts are read-only; only report directory is writable. No host namespace joins.
"""
import argparse, os, pathlib, shutil, subprocess, sys

def build(runtime, image, target, output, extra):
    if not image.startswith('sha256:') and '@sha256:' not in image:
        raise ValueError('image must be pinned to sha256 digest')
    executable = shutil.which(runtime)
    if not executable: raise RuntimeError('container runtime missing')
    target, output = pathlib.Path(target).resolve(strict=True), pathlib.Path(output).resolve(strict=True)
    if not target.is_dir() or not output.is_dir(): raise ValueError('mounts must be directories')
    if target == output or target in output.parents or output in target.parents:
        raise ValueError('target and output directories must not overlap')
    forbidden = {'--update', '--collect-android', '--allow-external-collector', '--latest'}
    if forbidden.intersection(extra): raise ValueError('external collectors and updates are forbidden')
    return [executable, 'run', '--rm', '--pull=never', '--network=none', '--read-only',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128',
            '--memory=1g', '--cpus=2', '--user=65534:65534',
            '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m',
            '--mount', f'type=bind,src={target},dst=/evidence,readonly',
            '--mount', f'type=bind,src={output},dst=/reports',
            image, 'python', '-X', 'utf8', 'scan/zero-breach-toolkit.py',
            '--no-menu', '--no-banner', '--no-feeds', '--scan-type', 'targeted', '--target', '/evidence'] + extra

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime', choices=('docker','podman'), default='podman')
    p.add_argument('--image', required=True)
    p.add_argument('--target', required=True)
    p.add_argument('--output', required=True)
    a, args=p.parse_known_args()
    if args and args[0]=='--': args=args[1:]
    try: return subprocess.run(build(a.runtime,a.image,a.target,a.output,args),timeout=1800).returncode
    except (ValueError,RuntimeError,OSError,subprocess.TimeoutExpired) as exc:
        print('Containment not proven; refusing execution:',exc,file=sys.stderr);return 125
if __name__=='__main__': raise SystemExit(main())
