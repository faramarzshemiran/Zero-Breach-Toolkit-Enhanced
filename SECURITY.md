# Security policy

Zero Breach Toolkit is used by people who may be targeted by a state-grade adversary, so
its own integrity matters as much as what it detects.

## Reporting a problem

Report security issues in the toolkit privately, not as a public issue. That includes any
way to make it leak data, contact the network during a scan, read more than it should,
misreport a result, or otherwise put a user at risk.

- Preferred: open a **private security advisory** on this repository (the "Security" tab,
  then "Report a vulnerability").
- If you cannot, message the project on Telegram: https://t.me/+t9gq13mSKcE4NGI0

Include what you found, how to reproduce it and the impact. We will acknowledge it,
investigate, and credit you if you wish.

## In scope

- The scanner reading, decrypting or transmitting anything it should not.
- Any path that makes the scanner touch the network during a scan.
- A result that is wrong in a way that misleads a user (a false "clean", a mislabelled
  severity, a missed gap).
- The update path (`--update`) fetching from outside its allow-list, or a tampered or
  changed cached indicator file being accepted at scan time.
- The build producing a file that does not match its source.

## Not a vulnerability

- **A clean result is not a guarantee.** The tool says so itself. Spyware of this grade is
  built to defeat retrospective checks; missing a real infection is a documented
  limitation, not a bug.
- A false alarm on a benign indicator match is a tuning issue. Report it as a normal issue.

## Verifying the tool

Do not run a security tool on trust. Each release publishes the SHA-256 of its files, and
the single-file build is reproducible: you can rebuild `dist/zero-breach-toolkit.py` from
source and confirm it matches. Signed releases also include detached GPG signatures made
with ArchiveGenocide's established release key; check its full fingerprint against the
official publisher page before trusting a downloaded key. See
[docs/VERIFYING.md](docs/VERIFYING.md).

## Indicators

The indicator set is curated to avoid false alarms against real people: known compromised
victim sites and ambiguous legitimate domains are excluded. Historical domains can change
ownership later. If an indicator here looks wrong, or could match legitimate traffic,
please report it. A false positive from this tool can send an innocent person to a crisis
helpline.
