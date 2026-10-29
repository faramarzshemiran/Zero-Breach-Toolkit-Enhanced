#!/usr/bin/env python3
"""Diagnostic gate: verify OS enforcement supplied by deployment owner. Never self-certifies."""
import argparse,json,os,pathlib,platform,sys

def verify(record):
    required=('platform','os_build','network_egress_test','child_egress_test','filesystem_test','privilege_test','tester','timestamp','test_artifact_sha256')
    if any(not record.get(x) for x in required): return False
    if record['platform'].lower()!=platform.system().lower(): return False
    if any(record[x] != 'pass' for x in ('network_egress_test','child_egress_test','filesystem_test','privilege_test')): return False
    return True

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence',required=True);a=p.parse_args()
    try:
        data=json.loads(pathlib.Path(a.evidence).read_text())
        if not verify(data): raise ValueError('incomplete, failing or wrong-platform test evidence')
        print('Evidence schema checks passed; reviewer authenticity and testing still require independent checks')
        return 0
    except (OSError,ValueError) as e:
        print('NOT ATTESTED:',e,file=sys.stderr);return 3
if __name__=='__main__':sys.exit(main())
