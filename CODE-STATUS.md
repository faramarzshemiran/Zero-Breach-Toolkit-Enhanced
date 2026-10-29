# Code status — 0.6.0-security-integration

Date: 29 October 2026. Based on v0.5.0 archive. Test environment: Linux Python; no native Windows/macOS/iOS/Android tests and no independent penetration-testing laboratory.

## Verified locally
- Original UTF-8 launcher and version output execute.
- Security suite **30 tests pass**; all-suite **552 tests run, 21 skipped, zero failures**.
- Python compilation and preview run.
- Source inventory manifest matches shipped Python source (hash manifest is not a publisher signature).
- Production-readiness gate **rejects** release (exit 3).

## Implemented in 0.6.0
1. `--encrypted-json` hooked into ordinary report generation; JSON serialised in memory then AES-256-GCM/scrypt encrypted into a private atomic no-overwrite file. Passphrase prompted, not passed in argv. Mutually excludes direct full plaintext report/bundle modes.
2. Full JSON plaintext export requires a private POSIX report directory. Sharing summary remains distinct.
3. `tools/container_run.py` restricts offline scanner in a digest-pinned, no-pull, no-network, read-only, low-privilege container, conditional on an independently verified image and runtime. Read-only evidence mount.
4. `tools/sign_release.py` creates an Ed25519 signature over hashed source entries when an owner-managed key exists. Existing `tools/verify_signed_release.py` verifies signatures/digests.
5. `tools/platform_attest.py` checks supplied native testing evidence schema without claiming independent authenticity.
6. Windows helper for programme-specific outbound firewall rule and an explicit macOS fail-closed guidance script.
7. Added tests verifying CLI flags, encryption output behaviour, image pinning restrictions, attestation rejection, original entrypoint, and previous regression tests.

## Unresolved / not claimable as complete
- Windows/macOS cross-process, firewall-wide and filesystem OS containment (scripts are advisory or partial; not fully enforced).
- Linux mount/user/PID namespace confinement with independent kernel-level escape testing. Strict launcher covers network namespace; container profile is runtime dependent and not verified here.
- Filesystem isolation on original direct launch command; it remains an ordinary application, without a sandbox.
- Android third-party collector is still quarantined; no independently authenticated collector artefact or functional validation available.
- End-to-end encryption of **all** reports, logs, intermediate temporary files, share output and phone acquisition artefacts; current coverage is the new `--encrypted-json` path only.
- Full central subprocess allow-list wired into every original workflow. Windows PowerShell calls already use absolute known paths, but other paths need manual audit.
- Signed final publisher ZIP and trusted independent key distribution. The included archive lacks a publisher signature.
- Full test coverage for native macOS, Windows, Linux permissions, phone hardware, and real-world malicious-sample accuracy; 21 existing tests skipped.
- Independent forensic source review, external penetration test, signed test attestations, cross-platform performance benchmark and documented threat-modelling sign-off.

**Release classification:** hardening development build, not production-qualified. None of the unresolved items above may be represented as certified or completed. To qualify for security-sensitive production, the owner must produce trusted signing keys, hardware/VM access, independent test artefacts and pass all applicable release checks.
