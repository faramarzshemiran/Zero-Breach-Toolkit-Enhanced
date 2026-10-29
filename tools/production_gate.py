#!/usr/bin/env python3
"""Production release gate requiring independently supplied attestations.
An unsigned or self-asserted JSON document is never accepted as certification.
"""
import argparse, json, pathlib, sys
MANDATORY=('linux_native','macos_native','windows_native','android_collector','external_penetration_test','artefact_privacy','publisher_signature')
def check(report):
    missing=[]
    for name in MANDATORY:
        record=report.get(name,{})
        if record.get('result') != 'pass' or not record.get('evidence_sha256') or not record.get('independent_reviewer'):
            missing.append(name)
    return missing

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--attestations',required=True);a=ap.parse_args()
    try: record=json.loads(pathlib.Path(a.attestations).read_text(encoding='utf-8'))
    except (OSError,ValueError) as e: print('Gate failed:',e,file=sys.stderr);return 3
    missing=check(record)
    # A JSON assertion by itself is never sufficient to validate provenance.
    print('NOT CERTIFIED: attestation documents require separate cryptographic and reviewer identity verification')
    if missing: print('Missing:',', '.join(missing))
    return 3
if __name__=='__main__': sys.exit(main())
