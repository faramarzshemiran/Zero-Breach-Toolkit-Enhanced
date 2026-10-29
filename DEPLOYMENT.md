# Zero Breach Toolkit v0.4.0 — deployment and test commands

**Status: SECURITY VALIDATION CANDIDATE, NOT CERTIFIED FOR PRODUCTION.** A successful Python test run does not demonstrate cryptographically trusted releases, operational integrity of downloaded code, all-platform firewall isolation, mobile acquisition authenticity or independent penetration testing. No tool can prove a device free from compromise.

## Install and baseline checks (all supported desktops)
Use Python 3.10+ from a trusted installation. Extract into a non-shared, non-synchronised directory, do not run as administrator/root. From the top-level `Zero-Breach-Toolkit-main` folder:

```sh
python -X utf8 tools/verify_manifest.py
python -X utf8 -m compileall -q scan tools
python -X utf8 security-test.py --suite security --verbose
python -X utf8 security-test.py --suite all --timeout 360
python -X utf8 tools/security_audit.py --json local-source-inventory.json
python -X utf8 tools/security_audit.py --require-production
```

`--require-production` **must** fail until the independently verified assurances are fulfilled. A `RELEASE-SHA256.json` is an accidental-tampering check only, and cannot authenticate a publisher because the manifest is distributed in the same ZIP. On macOS/Linux replace `python` with `python3` if appropriate, on Windows use `py -3`.

## Original invocation: retained

```sh
python -X utf8 scan/zero-breach-toolkit.py
```

macOS/Linux: `python3 -X utf8 scan/zero-breach-toolkit.py`.

## Offline use

**Linux fail-closed isolated scan:** Requires functioning `unshare --net` permission, verified outside the scanner. This creates a Linux network namespace for Python and descendant programmes. If this cannot run the wrapper refuses to fall back:

```sh
python3 -X utf8 tools/secure_run.py --profile offline-strict -- --no-menu --no-banner --quick --json ./private-results/report.json
```

Prepare output with `umask 077; mkdir -p private-results; chmod 700 private-results` first. Do not use network-mounted folders.

**Windows/macOS**: No independently certified kernel sandbox included. Apply a device/VM firewall deny-all rule covering interpreter and *all child processes* and confirm it with packet capture or a controlled egress test before scanning; then run:

```sh
python -X utf8 tools/secure_run.py --profile offline-standard -- --no-menu --no-banner --quick
```

The standard profile is **NOT OS-isolated**. Run offline standard only after external egress controls are in place.

Direct ordinary offline scan (legacy behaviour, no OS containment claim):

```sh
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --quick
```

Targeted folder scan:

```sh
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --scan-type targeted --target ./samples
```

## Controlled online indicator refresh (a separate operation)

Do not provide raw scans, reports or private information to update commands. Apply external firewall egress restrictions to official feed hosts. Confirm publisher hashes and update sources before use; default update uses pinned sources and SHA-256, but is not publisher-signed. This stage requires temporary network access:

```sh
python -X utf8 tools/update_indicators.py
```

After network access is revoked, run the scanner offline with the cached pinned indicators using the **original** command (omit `--no-feeds`):

```sh
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --quick
```

Offline-strict launcher excludes online indicators intentionally; for offline scanning with cached feeds, establish independently verified OS isolation and use direct original command.

## Devices

iPhone/iPad: supported *local backups only*, not live device instrumentation; supply with `--phone /private/backup/path`. Android: the remote collector has been disabled in this hardened candidate. Collect independently under a separately reviewed, signed acquisition process and use `--phone /private/export`. Never run downloaded collector binaries automatically.

## Release gates

1. Cross-platform tests on actual macOS, Windows, Linux builds with documented versions.
2. Confirm OS egress isolation by packet capture including descendant processes, DNS, IPv4, IPv6 and UDP.
3. External collector independently signed/verified or keep disabled.
4. Verify publisher-signed software/dependencies, SBOM and pinned digest of every deployed executable.
5. Fuzz scanners against malicious artefacts, symlinks and oversized files; validate output confidentiality and deletion.
6. Independently review detection accuracy and false positives/negatives using consented fixtures.
7. Independent penetration test, remediation sign-off and incident/rollback playbooks.

Until these release gates are evidenced, do not classify this release as security-sensitive production-ready.
