"""Record iPhone database table layouts for the iOS version test matrix.

Reads an unencrypted (or already decrypted) iPhone backup tree laid out as
DOMAIN/relativePath, or an extracted full file system (private/var/...), and
writes only the CREATE TABLE statements of the tables the iPhone reader uses.
No rows, values or file contents are recorded; nothing is written to the
evidence. The result is added to scan/tests/data/ios_layouts.json under the
iOS version given, and test_ios_version_layouts.py rebuilds each table from
it, plants indicators and checks that every reader still finds them.

    python tools/capture_ios_layouts.py TREE --ios-version 17.3
"""
import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = os.path.join(ROOT, "scan", "tests", "data", "ios_layouts.json")

# artifact name -> (path suffixes, in order of preference; tables the reader queries)
ARTIFACTS = {
    "sms": (("Library/SMS/sms.db",), ("message", "handle", "attachment")),
    "safari-history": (("Library/Safari/History.db",), ("history_items", "history_visits")),
    "data-usage": (("Library/Databases/DataUsage.sqlite",), ("ZPROCESS",)),
    "netusage": (("networkd/db/netusage.sqlite", "networkd/netusage.sqlite"), ("ZPROCESS",)),
    "tcc": (("Library/TCC/TCC.db",), ("access",)),
    "interactions": (("CoreDuet/People/interactionC.db",), ("ZINTERACTIONS",)),
    "webkit-statistics": (("ResourceLoadStatistics/observations.db",), ("ObservedDomains", "observed_domains")),
    "browser-state": (("Library/Safari/BrowserState.db",), ("tabs",)),
    "safari-tabs": (("Library/Safari/SafariTabs.db",), ("bookmarks",)),
    "cloud-tabs": (("Library/Safari/CloudTabs.db",), ("cloud_tabs",)),
    "safari-bookmarks": (("Library/Safari/Bookmarks.db",), ("bookmarks",)),
    "calls": (("CallHistoryDB/CallHistory.storedata",), ("ZCALLRECORD",)),
    "calendar": (("Library/Calendar/Calendar.sqlitedb",), ("CalendarItem",)),
    "shortcuts": (("Library/Shortcuts/Shortcuts.sqlite",), ("ZSHORTCUT", "ZSHORTCUTACTIONS")),
    "whatsapp": (("ChatStorage.sqlite",), ("ZWAMESSAGE",)),
}


def find(tree, suffixes):
    """The shortest matching path for the first suffix that matches anything."""
    for suffix in suffixes:
        found = []
        for dirpath, _dirs, files in os.walk(tree):
            for name in files:
                path = os.path.join(dirpath, name)
                if path.replace(os.sep, "/").endswith("/" + suffix):
                    found.append(path)
        if found:
            return min(found, key=len)
    return None


def layouts(path, tables):
    """CREATE TABLE text for the wanted tables, read from a private copy so a
    pending WAL journal is applied without touching the evidence."""
    work = tempfile.mkdtemp(prefix="zbt_layout_")
    try:
        for ext in ("", "-wal", "-shm"):
            if os.path.exists(path + ext):
                shutil.copyfile(path + ext, os.path.join(work, "db" + ext))
        con = sqlite3.connect(os.path.join(work, "db"))
        try:
            rows = con.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall()
        finally:
            con.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    wanted = {t.lower() for t in tables}
    return {name: sql for name, sql in rows if name.lower() in wanted and sql}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tree", help="decrypted backup tree or extracted file system")
    parser.add_argument("--ios-version", required=True, help="iOS version the tree comes from, e.g. 17.3")
    parser.add_argument("--output", default=OUTPUT)
    args = parser.parse_args()

    recorded = {}
    for artifact, (suffixes, tables) in ARTIFACTS.items():
        path = find(args.tree, suffixes)
        if not path:
            continue
        try:
            found = layouts(path, tables)
        except sqlite3.Error as exc:
            print("  {}: unreadable ({})".format(artifact, exc), file=sys.stderr)
            continue
        if found:
            recorded[artifact] = found
            print("  {:<18} {}".format(artifact, ", ".join(sorted(found))))
    if not recorded:
        raise SystemExit("no supported databases found under " + args.tree)

    data = {"versions": {}}
    if os.path.exists(args.output):
        with open(args.output, encoding="utf-8") as fh:
            data = json.load(fh)
    data["versions"][args.ios_version] = recorded
    data["versions"] = dict(sorted(data["versions"].items(), key=lambda kv: [int(p) for p in kv[0].split(".")]))
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=1, sort_keys=False)
        fh.write("\n")
    print("recorded iOS {}: {} databases -> {}".format(args.ios_version, len(recorded), args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
