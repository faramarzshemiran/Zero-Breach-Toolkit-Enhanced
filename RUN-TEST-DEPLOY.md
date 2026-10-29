# Zero Breach Toolkit v0.6.0 — commands and deployment

**Assurance status: DEVELOPMENT / NOT approved for security-sensitive production.**
This release implements additional security features but is not independently certified. Run in an isolated disposable VM, preferably offline, especially when examining compromised evidence. Host-level attackers can subvert in-host scans.

## Prerequisites
Python >=3.10 (check `python --version`), with dependencies reviewed before installation. `cryptography` is needed for evidence encryption and Ed25519 signing/verification. Install with `python -X utf8 -m pip install cryptography` in an isolated virtual environment (prefer a vetted offline wheelhouse). Never install packages automatically on a compromised host.

## Original interactive command (maintained)

```sh
python -X utf8 scan/zero-breach-toolkit.py
```

On macOS or Linux, use `python3 -X utf8` if `python` is absent.

## Tests (run in unpacked Zero-Breach-Toolkit-main directory)

```sh
python -X utf8 security-test.py --suite security --verbose
python -X utf8 security-test.py --suite all --timeout 360
python -X utf8 -m compileall -q scan tools
python -X utf8 tools/verify_manifest.py
python -X utf8 scan/zero-breach-toolkit.py --version
python -X utf8 scan/zero-breach-toolkit.py --preview --no-banner
python -X utf8 tools/security_audit.py --require-production
```
The final command **must fail (exit 3)** until external production evidence is established. Do not override it by editing evidence flags.

## Ordinary offline scan

```sh
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --quick
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --scan-type targeted --target ./samples
```
This is application-level offline mode; it is **not** an OS network isolation guarantee.

## Encrypted scan output (direct, no intermediate plaintext JSON)

Create a private results directory first (`mkdir private-results` and `chmod 700 private-results` on Unix; on Windows set restrictive ACLs and choose a private local directory). Then:

```sh
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --quick --encrypted-json private-results/case.zbe
python -X utf8 tools/evidence_vault.py decrypt private-results/case.zbe private-results/restored.json
```
Passphrase is requested in the terminal, not argv. The scanner still emits a human-readable report to the console; do not redirect it to a public logfile. Other explicit output options and some temporary scanner workflows are **not yet encrypted**; encrypted JSON only covers this output mode. The decrypted report is plaintext and must be protected.

## Linux strict network isolation (may fail if namespaces denied)

```sh
python3 -X utf8 tools/secure_run.py --profile offline-strict -- --no-menu --no-banner --quick
```
Uses Linux network namespace and fails closed if unavailable. Does not constitute full filesystem/process confinement. Confirm network isolation independently with test probes before sensitive use.

## Digest-pinned, no-network, restricted container profile (Docker or Podman)

Supply a **separately reviewed and locally installed** container image, pinned to its full digest. The release does not publish or authenticate such an image. The command refuses image pulls and network access, drops capabilities, sets no-new-privileges, uses a read-only root filesystem, bounds processes/memory/CPU, read-only mounts target evidence, and writes only to explicitly mounted reports path. This is conditional on container-runtime and host security, and user namespace/rootless capabilities.

```sh
python3 -X utf8 tools/container_run.py --runtime podman --image 'local/zero-breach@sha256:REPLACE_WITH_VERIFIED_DIGEST' --target ./samples --output ./private-results -- --quick --json /reports/report.json
```
The image must be provisioned separately, with exact source tree and digest verified. A detached image plus a digest string is not proof of authenticity. Do not pass privileged runtime flags. The `--json` report destination needs restrictive mount directory permissions. Avoid using unreviewed images.

## Online indicator updates (separate network permission)

```sh
python -X utf8 tools/update_indicators.py
```
Do this on a trusted update workstation using restricted egress and review feed provenance. Then transfer verified/cache files via a controlled process to the offline scanning host. To prohibit both cache use and network, add `--no-feeds` to your scan. A pinned hash is an integrity check and is not proof of publisher identity.

## Windows and macOS specific notes

Windows (admin PowerShell), to block **only the specified Python executable**:

```powershell
powershell -NoProfile -File tools/windows-offline-firewall.ps1 -PythonPath 'C:\Python313\python.exe'
python -X utf8 scan/zero-breach-toolkit.py --no-menu --no-banner --no-feeds --quick
powershell -NoProfile -File tools/windows-offline-firewall.ps1 -PythonPath 'C:\Python313\python.exe' -Remove
```
This firewall rule is NOT sufficient to block subprocesses, system services, other Python installations or alternate network paths. Use a physically disconnected and independently tested VM for high-assurance scanning.

macOS: `sh tools/macos-offline-guidance.sh` deliberately returns 3; no claims are made about native sandbox enforcement. Use a disconnected VM and verify egress with a separate probe.

## Signing a release (by publisher only)

Use a pre-existing owner-managed Ed25519 PEM signing key kept off the scanning host. Do **not** distribute the private key. The verifier public key must be distributed via a different authenticated channel. From an isolated signing machine:

```sh
python -X utf8 tools/sign_release.py --root . --private-key /secure/owner-release-key.pem --manifest release-manifest.json --signature release-manifest.sig
python -X utf8 tools/verify_signed_release.py --root . --manifest release-manifest.json --signature release-manifest.sig --trusted-public-key /secure/trusted-ed25519-public-key.base64
```
The verifier expects a raw Ed25519 public key encoded in Base64; signer creation/export/public-key distribution are the release authority's responsibility. Both manifest and signature are no-clobber. The supplied ZIP is **not signed**.

## Exit codes and limitations

Scanner documents scan-result exit codes in `--describe`; the production gate returns 3 on missing attestation; container wrapper returns 125 on containment failure. The tests here have not established device coverage, Android collector provenance, true host compromise resistance, end-to-end confidentiality of every temporary file, or native Windows/macOS confinement.
