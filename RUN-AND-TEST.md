# Zero Breach Toolkit v0.3.0 hardening preview — run and test

This source is NOT certified to the full 18-control remediation standard. Keep a firewall-based deny-all outbound rule in place for local scanning; the in-process Python network guard does not block child processes. No scan can prove a device clean. iOS/iPadOS require a supported backup; Android requires acquisition outside this scanner. Do not run an external collector without independent verification.

## Original command (preserved)

From the repository root, with Python 3.10 or newer:

```sh
python -X utf8 scan/zero-breach-toolkit.py
```

On macOS/Linux where the executable is called `python3`:

```sh
python3 -X utf8 scan/zero-breach-toolkit.py
```

On Windows (if `python` is not registered):

```powershell
py -3 -X utf8 scan/zero-breach-toolkit.py
```

## Automated test harness (no intentional online or physical device testing)

```sh
python -X utf8 security-test.py --suite security --verbose
python -X utf8 security-test.py --suite all --timeout 240
python -X utf8 -m compileall -q scan/zbtriage
python -X utf8 tools/security_audit.py --json local-source-inventory.json
python -X utf8 tools/security_audit.py --require-production
```

The `--require-production` command is **expected to fail with exit status 3**, documenting missing OS, collector and independent audit attestations. Running a passing suite does not waive this gate. `security-test.py --suite security` selects both security test modules in this release.

## Operating the scanner

```sh
python -X utf8 scan/zero-breach-toolkit.py --version
python -X utf8 scan/zero-breach-toolkit.py --preview --no-banner
python -X utf8 scan/zero-breach-toolkit.py --describe --no-banner
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --quick
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --quick --share-json ./summary.json
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --scan-type targeted --target ./samples
```

For confidential full JSON, use a private directory:

```sh
umask 077
mkdir -p ./private-results
chmod 700 ./private-results
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --json ./private-results/findings.json
```

On Windows, create a folder protected by your user account's NTFS permissions rather than relying on POSIX chmod. JSON full-output directory hardening is available as a programmatic `write_json(..., require_private_dir=True)` opt-in, not yet enforced across all output formats.

## Remaining critical work (not implemented / not certified)

* Independently tested OS-based sandbox/firewall egress confinement for Python **and all descendants** on each supported OS.
* Remove the unverified Android collector acquisition path or implement independently attested binaries and signature validation.
* A fully allow-listed central subprocess broker with strict output/time limits for every platform command.
* Encrypted evidence, privacy-safe logs, private scratch for every format, signed publisher manifests, dependency provenance and reliable rollback.
* Hostile-input fuzzing, race-resistant file-descriptor-based traversal, cross-platform CI, mobile-device lab tests and independently reviewed detection accuracy.

See the October 2026 remediation specification for the complete 18-control definition of done.
