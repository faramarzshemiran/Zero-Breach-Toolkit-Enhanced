# Zero Breach Toolkit — security hardening implementation record

**Build:** 0.2.0-security-preview, 29 October 2026. **Status:** development preview; not certified safe.

## Executive summary

This is the original 0.1.11 source plus a narrowly scoped, tested hardening increment. It is **not** an implementation of all 18 controls of the October 2026 technical specification. The revised CLI blocks unapproved third-party Android collector execution before it can download or launch anything, makes a high-assurance network-isolation request fail closed where OS enforcement has not been proven, centralises the scan/update/acquisition trust boundary, and ensures POSIX JSON reports are private (0600). Existing IOC detection and platform readers are retained.

## Changes and requirement traceability

| Requirement | What is implemented | Remaining work |
|---|---|---|
| SEC-001 | `security_policy.RunPolicy` separates offline, update, acquire; invalid combinations fail | Dedicated process isolation and OS-enforced egress blocking on each platform |
| SEC-002 | `--high-assurance` refuses to run rather than claiming unverified sandboxing | Deploy and verify actual platform sandbox and privilege boundaries |
| SEC-003 / SEC-004 | Android executable download/execution is **off by default**; unlock requires `--allow-external-collector`, plus original interactive consent and SHA-256 checks | Independently attest collector publisher signature, supply chain and runtime behaviour; secure subprocess broker for all modules |
| SEC-005 / SEC-006 | JSON report temporary files are set to 0600 on POSIX, preserving atomic replace | Output confidentiality by default across every format; recipient encryption and scratch directory ownership checks |
| SEC-007–SEC-018 | Existing code and regression tests retained; 18 requirements used as future development baseline | Not fully remediated. See original specification for individual gates. |

**Important:** `--allow-external-collector` is a warning-backed escape hatch for users who have independently audited the external binary. It is **not** an attestation. Never pass it solely because a test succeeded.

## Quick start — macOS / Linux

Run these commands in the extracted **Zero-Breach-Toolkit-main** folder; Python 3.10+ recommended:

```sh
python3 --version
python3 security-test.py --suite security --verbose
python3 security-test.py --suite all --timeout 240
python3 -m compileall -q scan/zbtriage
python3 scan/zero-breach-toolkit.py --version
python3 scan/zero-breach-toolkit.py --describe --no-banner
python3 scan/zero-breach-toolkit.py --preview --no-banner
python3 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --quick --share-json ./share-summary.json
```

For a private full local JSON report (can contain highly sensitive records):

```sh
umask 077
mkdir -p ./private-results
chmod 700 ./private-results
python3 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --json ./private-results/findings.json
```

For a specific local directory:

```sh
python3 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --scan-type targeted --target ./samples --share-json ./summary.json
```

**Windows PowerShell** (from the extracted repository directory):

```powershell
py -3 --version
py -3 security-test.py --suite security --verbose
py -3 security-test.py --suite all --timeout 240
py -3 -m compileall -q scan/zbtriage
py -3 scan/zero-breach-toolkit.py --version
py -3 scan/zero-breach-toolkit.py --preview --no-banner
py -3 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --quick --share-json .\share-summary.json
```

Windows output protection relies on operating-system ACLs and user-controlled storage. No automatic ACL verification has yet been implemented; choose a private folder.

## Tests and expected behaviour

`security-test.py --suite all` runs all `scan/tests/test_*.py` with Python's built-in unittest. The suite is designed to use mocks and fixtures, but developers should review tests before running on sensitive equipment. It does **not** automatically run network update, physical device, OS firewall, spyware samples, or real administrative privilege tests. `--suite security` runs only the 8 new trust-boundary regression tests. A non-zero exit code blocks release. A skipped test is not a passing test.

Additional manual negative checks:

```sh
python3 scan/zero-breach-toolkit.py --high-assurance --no-menu --no-banner
python3 scan/zero-breach-toolkit.py --collect-android ./collection --no-menu --no-banner
```

Both **must fail** without performing a scan, downloading a binary or launching a collector. Exit code 1 is expected. Do not use the collection unlock flag during automated tests or without a separately verified binary.

CLI exit codes for ordinary scans retain original meaning: 0 no actionable findings; 2 actionable indicators; 3 incomplete coverage without actionable indicators; 1 errors. A clean result is never proof the device is uncompromised.

## Validation performed in the supplied Linux build environment

- Built-in Python tests: **530 run, 509 passed, 21 skipped, 0 failures**.
- New security tests: **8 passed**.
- `compileall`, `--version`, `--describe`, `--preview`: passed.
- Not tested: macOS, Windows, Android device or iPhone, live OS-level network capture and denial, collector signature/runtime behaviour, penetration/fuzz testing, encryption, SBOM signing, performance budgets.

## Outstanding release blockers

1. OS-level deny-all network egress for the scanner and all child processes, demonstrated on each supported OS.
2. Privilege-free subprocess broker and allow-listed programme execution with signed/attested external binaries.
3. Safe private scratch, reliable crash cleanup, redacted defaults and authenticated recipient encryption for complete evidence.
4. Secure update manifest signatures, release provenance, SBOM, dependency lockfiles and repeatable builds.
5. Parser fuzzing, hostile archive and symlink race tests, resource limits and cancellation tests.
6. Privacy-safe logging and structured module coverage/completeness reports with adversarial accuracy fixtures.
7. macOS/Windows/Linux integration tests, physical mobile-device test matrix and measured performance under load.
8. Independent security review plus signed release approval before any claim of production safety.

Do not deploy to a high-risk user's device as a fully hardened version until those gates are met.
