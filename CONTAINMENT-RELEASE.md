# Zero Breach Toolkit v0.6.3 — Containment validation candidate

## Security changes
- Windows: fail closed unless virtual machine identity is recognised, execution is elevated *inside that VM*, and all guest networking adapters are disconnected. Existing firewall rules and outbound policy are checked; original profile policy is restored in a `finally` block. Run only in a disposable VM; the guest firewall is defence in depth, not a substitute for hypervisor networking isolation.
- macOS: sandbox launcher now also rejects root. Deprecated `sandbox-exec` has no supported high-assurance status; use a networkless VM for sensitive work.
- Egress diagnostics: four IPv4/IPv6 endpoint/port combinations and isolated Python child-process attempts. No application payloads. Failure to connect may simply indicate no route; the probe cannot certify isolation.
- Five new static/mocked tests. The original interactive launcher remains unchanged.

## Commands (from project root)
`python -X utf8 scan/zero-breach-toolkit.py` (original interactive mode, not sandboxed)

`python -X utf8 security-test.py --suite security --verbose`

`python -X utf8 security-test.py --suite all --timeout 360`

`python -X utf8 tools/verify_manifest.py`

`python -X utf8 tools/containment_probe.py --mode strict`

Windows (administrator inside a **disconnected disposable VM**):
`powershell -NoProfile -ExecutionPolicy Bypass -File tools/windows-vm-offline.ps1 --no-menu --no-banner --quick`

macOS:
`mkdir -p private-results && chmod 700 private-results`
`python3 -X utf8 tools/macos_contained.py --output private-results --probe-only`
`python3 -X utf8 tools/macos_contained.py --output private-results -- --no-menu --no-banner --quick`

Linux:
`python3 -X utf8 tools/secure_run.py --profile offline-strict -- --no-menu --no-banner --quick`

## Validation and release status
This package is NOT certified for production. Windows/macOS binaries have NOT been executed on native operating systems here. Required: native firewall and sandbox tests, hypervisor breakout tests, UDP/DNS/proxy egress checks, host networking tests and independent penetration testing. Do not infer production assurance from unit-test pass counts or a successful smoke test.
