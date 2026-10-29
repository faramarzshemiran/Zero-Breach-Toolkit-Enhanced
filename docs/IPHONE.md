# Local iPhone evidence

These readers analyse local evidence you already have. They do not unlock a phone, create
a backup, download from iCloud, or run MVT.

## Input choices

Use the phone menu, or add these arguments to the source or standalone scanner:

| Evidence | Arguments |
|---|---|
| Finder / Apple Devices / iTunes backup | `--phone FOLDER` or `--phone FOLDER --ios-input backup` |
| Encrypted local backup | `--phone FOLDER --backup-password` (private terminal prompt) |
| Extracted file system rooted above `private/var` or `var` | `--phone ROOT --ios-input filesystem` |
| Sysdiagnose directory or TAR/TAR.GZ | `--phone PATH --ios-input sysdiagnose` |

Add `--preview` to see the scope without scanning, and `--json REPORT` for source and
record provenance and explicit coverage gaps. Select the backup folder that contains
`Manifest.plist` and `Manifest.db`, not a parent folder holding several devices. Names in a
sysdiagnose directory or archive are inventoried within bounds; only selected artifact
files are parsed.

### Encrypted backups

[Apple documents](https://support.apple.com/108353) why encrypted local backups can include
more history. Decryption needs the owner's password and the optional dependency in
`requirements-backups.txt`; nothing is installed automatically. Legacy SHA-1 and two-stage
SHA-256/SHA-1 key derivation, class keys and independently wrapped artifact keys are
supported. Each payload's padding is checked and the decrypted payload is used as copied,
because a live database often changes between the moment the backup records its size and
the moment it is copied. Wrong passwords, missing classes, bad wrapped keys, invalid
padding and missing payloads are gaps. There is no password recovery. AES-CBC does not
authenticate source evidence.

## Supported records

Readers require physical SQLite tables and supported columns. Optional columns may be
missing, which can reduce dates or metadata. A matching filename alone does not validate a
database. The table describes the implemented subset, not every schema of every iOS or app
release.

Where Apple renamed a table or column between releases, each known layout is listed and the
first one fully present is used. The layouts of iOS 15.3.1, 16.1.2, 17.3 and 18.0 are
recorded in `scan/tests/data/ios_layouts.json` (table definitions only), and the test suite
rebuilds every supported database from them, both as a backup and as an extracted file
system. `tools/capture_ios_layouts.py` records another release from a backup or extraction
you are entitled to examine.

| Artifact | Supported interpretation |
|---|---|
| Manifest and Info.plist | File inventory, installed app IDs, recorded iOS version. A copy without `Manifest.plist` whose file list is readable without a key is read as unencrypted; the missing file is a gap |
| SMS `message` | Plain text or supported inert NSKeyedArchiver / limited NSArchiver-v4 attributed text; Apple-epoch seconds or nanoseconds; only an integer incoming direction is `received`. System events with no text or encoded body (group renames, member changes) have nothing to search and are not gaps |
| SMS `handle`, `attachment` | Correspondent IDs and recorded attachment metadata; attachments are not opened |
| Safari history | Visits in the legacy path and `Library/Safari/Profiles/*/History.db`; the visit URL's host is graded separately from reference text |
| Safari tabs | `BrowserState.db` `tabs.url`; from iOS 15, `SafariTabs.db` `bookmarks.url` and `CloudTabs.db` `cloud_tabs.url` (tabs open on the owner's other devices); optional title; references |
| Safari bookmarks | `Bookmarks.db` `bookmarks.url`; references, not browsing or contact |
| Chrome / Firefox | Default and discovered supported profiles, with the local-visit rules in [METHODOLOGY.md](METHODOLOGY.md) |
| Chromium connection records | `Network Persistent State` in any app (Edge, Chrome, Opera and other Chromium-based iPhone browsers): servers the browser connected to, graded contacted |
| Brave | `Brave.sqlite` `ZDOMAIN.ZURL`: sites with their visit counts; references |
| WebKit in every app | Every iPhone browser and in-app browser uses WebKit, so each app's `observations.db` and URL `Cache.db` are read wherever they are |
| WebKit statistics | `ObservedDomains.registrableDomain` (older: `observed_domains`); references |
| URL cache | `cfurl_cache_response.request_key`; references, with no inference of successful contact. Other system stores named `Cache.db` are not URL caches and are skipped |
| DataUsage / netusage | `ZPROCESS` names, optional bundle IDs and process timestamps; netusage at `networkd/netusage.sqlite` or, on recent releases, `networkd/db/netusage.sqlite`; no schema guessing |
| WhatsApp | `ZWAMESSAGE` text, integer direction, optional date and sender; outgoing text stays a reference |
| TCC | `access` client and service plus supported grant columns; the client is compared as a bundle ID, an executable path or a process name (including a path's file name); configuration is not execution |
| Calls / Calendar / Interactions | `ZCALLRECORD` (address as text or UTF-8 bytes); `CalendarItem` (`summary`/`description` or `title`/`notes`) and `Participant.email` (invitees and organisers); `ZINTERACTIONS`. Identifiers and text only, with no inference of an exploit |
| Shortcuts | `ZSHORTCUT` names; inert plist action strings from `ZWORKFLOWACTIONS`, or from iOS 15 `ZSHORTCUTACTIONS.ZDATA` with the description; activation and execution unverified |
| ADDaily analytics | `netUsageBaseline` process tuples beginning with a plist date, plus explicit process/bundle fields |
| Profiles and profile events | Installed profiles (`profile-*.stub`, `.mobileconfig`): PayloadUUID and PayloadIdentifier. `MCProfileEvents.plist`: profile identifier, operation and time of each recorded install or removal. Other device-management files in that folder are searched for literal references only. Current activation unverified |
| Location clients / app metadata | `clients.plist` keys (`i` + bundle ID, `p` + path), `BundleId` and other supported identifiers; recorded metadata only |
| Global preferences | Recorded `LDMGlobalEnabled` state; no claim about current Lockdown Mode |
| iMessage/FaceTime lookups | `idstatuscache.plist` (Preferences, or IdentityServices from iOS 14.7): `mailto:` accounts matched to email indicators, with the lookup date; a lookup does not show who started the contact |
| Browser favicons | Safari `Favicons.db` (`page_url`, `icon_info`) and Chromium `Favicons` (`icon_mapping`, `favicons`); page and icon addresses are references |
| Web view site data | Sites that stored data in an app's web view or Safari View Service: `LocalStorage/*.localstorage` and `IndexedDB/v1/<site>` names, and from iOS 16 the `origin` file in each `WebsiteData/Default` folder; graded contacted. Local app pages (`file:` and app schemes) are skipped |
| Security analytics | File-system extractions only: `private/var/Keychains/Analytics/*.db` failure and note records (`Caller` and other identifiers, plus any host in the record), with the record time; device-log grade |
| WebKit resource plists | Literal string references; unsupported typed layouts are gaps |
| Sysdiagnose `ps.txt` | Executable path and name of every process running at capture time (graded as present on the device); command lines are searched for references |
| `mobile_installation.log` and rotations | App identifiers in install records and container creation, container paths. An app installed as a developer build goes under "worth a look" with its usual explanation |
| Shutdown logs and rotations | Structured remaining-client PID/path/UUID records and the following SIGTERM Unix time; unusual directories are leads only |
| Diagnostic reports | IPS crash identities (procName, procPath, bundleID); every process in memory-pressure (Jetsam) reports and stackshots, where a 32-character name may be the start of a longer indicator; Command/Process/Path lines in text reports; legacy Process/Path lines. Report kinds without a process identity are searched as text. Files with these names inside app containers, and macOS `._` AppleDouble files, are not treated as diagnostic reports. A report alone does not establish exploitation |

Unsupported attributed-body encodings are not searched as raw bytes, and attribute strings
cannot be mistaken for message text. The typedstream decoder is limited and does not cover
every variant.

Not covered: deleted records, attachment contents, general WebKit storage decoding, unified
logs, binary sysdiagnose plugins, full app inventories beyond supported metadata, and
arbitrary encrypted containers.

## Evidence integrity and limits

Original evidence is opened read-only. SQLite main files and independently decrypted WAL
sidecars are copied to temporary local storage. WAL headers, salts, page sizes and rolling
checksums are checked against SQLite's
[published format](https://sqlite.org/fileformat.html#walformat), and SQLite replays the
validated committed prefix on the copies. Damaged or truncated tails produce gaps; earlier
readable evidence is kept. Valid uncommitted tails and older salt epochs are not committed
records. SHM is regenerated. An encrypted root `Manifest.db` WAL has no independent artifact
key in this interface and is not replayed. This does not repair arbitrary corruption or
make files that change during the scan into a coherent acquisition.

Paths from backup databases select only validated hexadecimal blob IDs. File-system links,
reparse points and unsafe archive names are refused. Archive members are stored under
opaque temporary names, never extracted to supplied paths. Duplicate member names are
refused as ambiguous. Sparse and special entries are unsupported.

Limits: 256 MiB per artifact, 16 MiB before property-list decoding, 1 GiB of artifact
reads, 200,000 inventory entries, 32 directory levels, 256 additional artifacts, 4 GiB of
streamed TAR expansion and a 60-second archive traversal budget. SQLite fields, queries,
rows and text have their own limits, and per-report record caps apply. Hitting any limit
produces a gap. Reading the same source again for another table counts toward the byte
budget.

`hits[].provenance` records the original source or member, SHA-256 of the bytes read, input
format, encryption flag, parser ID, record locator and raw timestamp when available.
Database findings also include the WAL hash when one was read. For an encrypted artifact the
hash identifies the ciphertext, not the temporary plaintext. Inventory and Info findings can
carry less provenance than parsed artifacts. Hashes do not authenticate a device, prove the
acquisition is complete or establish compromise. Full reports are private; the sharing
summary leaves these fields out.

Temporary plaintext is removed on normal completion and on handled errors; a cleanup failure
is a gap. A killed process or power loss can leave temporary files, and removal is not
secure erasure. Keep sensitive evidence on protected local storage.

## References

The shutdown interpretation is informed by the
[original research](https://securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734/)
and [format documentation](https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc).
The implementation is independent; no MVT or iShutdown code is bundled.
