# Zero Breach Toolkit 0.5.0 — validation build (NOT production approved)

This is an engineering validation build. The original command remains:

    python -X utf8 scan/zero-breach-toolkit.py

On Unix systems use `python3` instead of `python` if required. Use Python 3.10+.

## Install and test

From inside `Zero-Breach-Toolkit-main`:

    python -X utf8 -m pip install -r requirements.txt
    python -X utf8 -m pip install cryptography
    python -X utf8 security-test.py --suite security --verbose
    python -X utf8 security-test.py --suite all --timeout 360
    python -X utf8 -m compileall -q scan tools
    python -X utf8 tools/verify_manifest.py
    python -X utf8 tools/security_audit.py --require-production

The final gate is expected to FAIL until trusted third-party attestations are supplied. A source hash manifest stored in the same archive is NOT a signature. Run commands from the extracted top-level repository directory. The package may use additional dependencies for particular scan types.

## Run: legacy interactive / offline / online update

    python -X utf8 scan/zero-breach-toolkit.py
    python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --quick
    python -X utf8 tools/secure_run.py --profile offline-standard -- --no-menu --no-banner --quick

`offline-standard` is only an application-policy guard; it is not an OS sandbox.

On compatible Linux hosts, strict sandboxed mode:

    python3 -X utf8 tools/secure_run.py --profile offline-strict -- --no-menu --no-banner --quick

This blocks networking via a separate Linux network namespace and fails closed if unavailable. Test on the target host and ensure any namespace privileges are narrowly scoped. The process still has the caller's filesystem permissions; protect results and run in a dedicated unprivileged account / externally controlled filesystem sandbox. Do not use root.

Online indicator refresh is an **explicit separate operation**:

    python -X utf8 tools/update_indicators.py

Disconnect network access before running the scanner. Never update from an untrusted network without independently verifying feed authenticity and transport. Other telemetry from the operating system is outside the Python scanner's control.

## File encryption (explicit step; does NOT erase existing plaintext)

    python -X utf8 tools/evidence_vault.py encrypt private-results/report.json private-results/report.zbe
    python -X utf8 tools/evidence_vault.py decrypt private-results/report.zbe private-results/restored.json

Requires `cryptography`. Passphrase is read interactively, never as a CLI argument. AES-256-GCM + scrypt with random salts/nonces and an authenticated format. No overwrite; max input 2 GiB; designed for local regular files. Plaintext results and filesystem backups remain and need separately managed secure retention. No guarantee of secure erasure from flash storage. Treat decrypted files as confidential. On Windows, use ACL-protected destination directories (POSIX 0600 does not map to Windows ACLs). No encryption-at-rest is automatically applied to the scanner's output.

## Authenticated publisher releases

Obtain `trusted-ed25519-public-key.base64` **independently** from your release authority; do not trust a key bundled with an unauthenticated ZIP. Publisher must sign exact raw bytes of the intended SHA-256 JSON manifest, publish detached base64 signature, and protect the private signing key offline.

    python -X utf8 tools/verify_signed_release.py --root . --manifest publisher-manifest.json --signature publisher-manifest.sig --trusted-public-key trusted-ed25519-public-key.base64

This tool does not create a publisher identity or approve a release. Supply-chain verification requires independently provisioned keys, signed attestations, locked dependency hashes, CI provenance and verification on a separate host. Release scripts should include every shipped file and refuse extraneous executable content.

## Production acceptance gates: MUST NOT mark complete on this build

1. Independent macOS, Windows and Linux EDR/network-egress tests of parent and child processes, with repeatable artefacts.
2. OS sandbox policy and unprivileged filesystem restrictions on each supported platform; Linux network namespace alone is insufficient.
3. Independent forensic review and author verification of Android collector, or permanently disable collector (currently quarantined).
4. Independent penetration test of parser inputs, archives, symlinks/reparse points, storage, hostile paths, subprocesses and malicious indicators.
5. Cross-platform hardware/device tests; measure detection false positives/false negatives on curated corpora.
6. Signed binaries and release source, pinned dependency lockfiles, externally stored verified signing key, reproducible builds and SBOM.
7. Confidentiality tests of all scan artefacts, logs, caches, crash dumps and deletion flows; automatic evidence encryption if mandated.
8. Formal threat-model review, sign-off by authorised owner and release gate with independently verifiable evidence.

The `--require-production` test is intentionally unsatisfied. This is a real limitation; do not bypass the gate or advertise this as independently certified production software.
