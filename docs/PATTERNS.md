# Optional Candiru file patterns

An optional check for Candiru files. The default scan does not run it.

## What it checks

`--patterns` scans local file bytes with two unchanged published Candiru rules:
Microsoft's 2021 DevilsTongue hijack-DLL rule and Malpedia's automatically generated
DevilsTongue rule, which was derived from unpacked files or memory dumps. A newer date on a
rule does not mean it covers a newer campaign. Neither rule proves infection, execution or
coverage of every Candiru build. This mode does not acquire or scan running memory, decrypt
payloads, inspect phone backups or add Pegasus detection.

## Setup

The default scanner needs only Python's standard library. Pattern scanning also needs
Python 3.9+ and the pinned official YARA-X 1.21.0 wheel. `requirements-patterns.txt` pins
the SHA-256 of every published wheel and rejects source builds. Install into a dedicated
environment:

```text
python -m venv .venv
<venv-python> -m pip install -r requirements-patterns.txt
<venv-python> scan/zero-breach-toolkit.py --patterns
```

The scanner never installs packages, downloads rules or contacts sample or indicator
servers. Without the engine it reports UNKNOWN with an explicit gap. Python 3.8 remains
supported for the default checks.

## Choosing what to scan

`--pattern-path ABSOLUTE_PATH`, repeatable, chooses files or folders for the pattern check.
Without it, the check uses the file-hash roots. It limits only the pattern check; browser,
hash and host checks keep their usual scope. `--quick` skips hashing but still runs
requested patterns.

Relative, redirected and cloud-recall paths are refused, as are Windows UNC paths and
remote drives. On POSIX systems a network-mounted directory can look like an ordinary
absolute path and may be read; use operating-system network isolation when strict offline
operation is required. Files are eligible whatever their extension. Per-file size and time
limits, traversal and total-byte limits, directory exclusions, unreadable files and other
gaps are listed in the module output. Reaching a limit is never treated as a completed clean
check.

## Reading a match

The JSON evidence grade is `file-pattern`, separate from exact-hash evidence (`on-disk`).
The readable report asks for review and keeps the rule's author, source and licence. A
pattern match needs investigation; it is not a measured detection rate or proof of broad
Candiru coverage. Rule provenance and original texts are in `third_party/candiru/`; these
rules are not covered by the indicator feed's CC0 grant.
