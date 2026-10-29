# Zero Breach Toolkit v0.6.1 — assurance candidate (NOT CERTIFIED)

## Security status
The codebase is **not approved for security-sensitive production deployment**. This build adds bounded egress/child-process diagnostics, a strict attestations checklist, and automated regression tests. None replaces a host-native penetration test. The release contains **no publisher signature**: a signing key and a verified release authority must be supplied independently. An arbitrary locally created key would not authenticate the publisher.

## Prerequisites
Python 3.10+; run from repository root. Use `python3` on macOS/Linux if `python` is unavailable. Install dependencies from vetted, pinned packages before using optional features; do not install dependencies on a compromised target.

## Launch / offline
```
python -X utf8 scan/zero-breach-toolkit.py
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --quick
python3 -X utf8 tools/secure_run.py --profile offline-strict -- --no-menu --no-banner --quick
```
The legacy command is **not** a full OS sandbox. The strict Linux launcher requires kernel network namespace permissions and fails closed otherwise. Its isolation only covers network egress, not universal process/filesystem isolation.

For a digest-pinned container image that has been independently audited and locally installed:
```
python3 -X utf8 tools/container_run.py --runtime podman --image my-audited-toolkit@sha256:REPLACE_WITH_REAL_DIGEST --target /path/to/evidence --output /path/to/private-results
```
The actual image must be built, audited and pinned by the deployer. The container launcher requests no network, a read-only root, all capabilities dropped, non-root UID, resource limits and read-only evidence mount. No pinned image is supplied with this build. This command is a template, not an executable as written.

## Online update (a distinct trust boundary)
```
python -X utf8 tools/update_indicators.py
```
Only run on a trusted network-connected workstation after verifying source authenticity. Transfer authenticated feeds to offline workstations through an approved, checked process.

## Automated tests and diagnostics
```
python -X utf8 security-test.py --suite security --verbose
python -X utf8 security-test.py --suite all --timeout 360
python -X utf8 -m compileall -q scan tools
python -X utf8 tools/verify_manifest.py
python -X utf8 tools/containment_probe.py
python -X utf8 tools/security_audit.py --require-production
python -X utf8 tools/production_gate.py --attestations /path/to/third-party-attestations.json
```
The standalone containment probe is **diagnostic only**. Run it *inside* the sandbox being evaluated; green results do not prove every egress path is blocked. The production gate never self-certifies and deliberately exits code 3, pending independently authenticated records.

## Encrypted evidence
```
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --quick --encrypted-json private-results/case.zbe
python -X utf8 tools/evidence_vault.py decrypt private-results/case.zbe private-results/restored.json
```
Review scanner options for any other output products before running sensitive cases. The encrypted-JSON option alone does **not** guarantee that all temporary files, logs, crash dumps, swap or ancillary exports are encrypted. Use a host with full-disk encryption and a vetted temporary-storage policy.

## Release signing — publisher responsibility
```
python -X utf8 tools/sign_release.py --root . --private-key /secure/path/issuer-ed25519.pem --manifest /safe/output/manifest.json --signature /safe/output/manifest.sig
python -X utf8 tools/verify_signed_release.py --root . --manifest /safe/output/manifest.json --signature /safe/output/manifest.sig --trusted-public-key /independently/verified/public-key.base64
```
A trusted signing authority must establish key provenance. These commands are examples: the first requires a real secured key. Never treat a generated test key as publisher identity.

## Mandatory independent completion gates
1. Native macOS sandbox containment, child-process and filesystem escape testing on supported macOS versions.
2. Native Windows firewall/process containment and child-process escape testing on supported Windows versions.
3. Native Linux container/namespace and privilege boundaries on the deployed kernels.
4. Independently sourced Android collector source, verified build/reproducibility, authenticated signatures, and live device testing.
5. Exhaustive audit of *all* intermediate artefacts and subprocess outputs, including failure, crash and interruption scenarios.
6. Independent penetration test and remediation retest with signed report and scope.
7. Publisher-controlled signing service, externally distributed trusted key, signed release, and verification in a clean environment.

**None of these external attestations is claimed to have passed by the package author.**
