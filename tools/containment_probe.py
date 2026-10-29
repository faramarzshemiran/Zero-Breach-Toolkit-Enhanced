#!/usr/bin/env python3
"""Limited TCP egress smoke test (not a certificate of network isolation).
No application data is transmitted. Connectivity failure can reflect routing.
Test independently of, and in addition to, OS-enforced containment.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

TARGETS = (
    ('ipv4_a', '1.1.1.1', socket.AF_INET, 443),
    ('ipv4_b', '8.8.8.8', socket.AF_INET, 53),
    ('ipv6_a', '2606:4700:4700::1111', socket.AF_INET6, 443),
    ('ipv6_b', '2001:4860:4860::8888', socket.AF_INET6, 53),
)

def blocked(host, family, port):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex((host, port)) != 0
    except OSError:
        return True

def probe(mode='strict'):
    results = {}
    for name, host, family, port in TARGETS:
        results['parent_' + name + '_blocked'] = blocked(host, family, port)
        code = ('import socket,sys; '
                's=socket.socket(%d,socket.SOCK_STREAM); '
                's.settimeout(.5); '
                'sys.exit(1 if s.connect_ex((%r,%d))==0 else 0)' % (family, host, port))
        try:
            run = subprocess.run([sys.executable, '-I', '-c', code], timeout=4, capture_output=True)
            results['child_' + name + '_blocked'] = run.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            results['child_' + name + '_blocked'] = False
    # Compatibility with the v0.6.2 public diagnostics keys.
    results['parent_ipv4_blocked'] = results['parent_ipv4_a_blocked']
    results['parent_ipv6_blocked'] = results['parent_ipv6_a_blocked']
    results['child_ipv4_blocked'] = results['child_ipv4_a_blocked']
    results['child_ipv6_blocked'] = results['child_ipv6_a_blocked']
    results['not_root'] = not hasattr(os, 'geteuid') or os.geteuid() != 0
    return results

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--json')
    p.add_argument('--mode', choices=['strict'], default='strict')
    args = p.parse_args(argv)
    results = probe(args.mode)
    report = {'results': results, 'all_pass': all(results.values()),
              'limitations': 'Outbound TCP only. Failed connections do not prove a firewall or sandbox is enforced. UDP, DNS, local proxying, IPv6 policy and native executables require separate OS-level testing.'}
    body = json.dumps(report, indent=2) + '\n'
    if args.json:
        target = Path(args.json)
        with target.open('x', encoding='utf-8') as fh:
            fh.write(body)
        if os.name == 'posix':
            target.chmod(0o600)
    print(body, end='')
    return 0 if report['all_pass'] else 3

if __name__ == '__main__':
    raise SystemExit(main())
