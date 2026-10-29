"""Black-box check of a packaged program against the single-file build.

    python tools/program_smoke.py PROGRAM [SINGLE_FILE]

Builds a harmless fixture (a Chromium profile whose history visited a
synthetic .invalid domain, and a file whose SHA-256 is listed as an indicator),
scans it with PROGRAM and with the single-file Python build through the
command line only, and requires both to find the same evidence. Nothing here
touches the network or the machine's own records. Exits non-zero on any
difference.
"""
import contextlib
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAIN = "program-smoke.invalid"
PAYLOAD = b"Harmless Zero Breach program check bytes; not malware.\n"


def fixture(base):
    profile = os.path.join(base, "target", "User Data", "Default")
    os.makedirs(profile)
    with open(os.path.join(base, "target", "User Data", "Local State"), "w", encoding="utf-8") as fh:
        fh.write("{}")
    with contextlib.closing(sqlite3.connect(os.path.join(profile, "History"))) as db:
        db.execute("CREATE TABLE urls(url TEXT,title TEXT,last_visit_time INTEGER)")
        db.execute("INSERT INTO urls VALUES(?,?,?)", ("https://" + DOMAIN + "/", "", 13000000000000000))
        db.commit()
    with open(os.path.join(base, "target", "sample.bin"), "wb") as fh:
        fh.write(PAYLOAD)
    feed = os.path.join(base, "feed.txt")
    with open(feed, "w", encoding="utf-8") as fh:
        fh.write(DOMAIN + "\tinfrastructure\tprimary\tprogram-smoke\n")
        fh.write(hashlib.sha256(PAYLOAD).hexdigest() + "\tsample\tprimary\tprogram-smoke\n")
    return os.path.join(base, "target"), feed


def scan(command, base, name, target, feed):
    report = os.path.join(base, name + ".json")
    proc = subprocess.run(command + ["--iocs", feed, "--scan-type", "targeted", "--target", target,
                                     "--no-banner", "--no-pause", "--no-menu", "--no-feeds",
                                     "--json", report],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=600)
    if not os.path.isfile(report):
        sys.exit("{}: no report written (exit {})\n{}".format(
            name, proc.returncode, proc.stdout.decode("utf-8", "replace")[-3000:]))
    with open(report, encoding="utf-8") as fh:
        doc = json.load(fh)
    hits = sorted({(h["indicator"], h["evidence"]) for m in doc["modules"].values() for h in m["hits"]})
    return proc.returncode, hits, doc


def main():
    program = os.path.abspath(sys.argv[1])
    single = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.join(ROOT, "dist", "zero-breach-toolkit.py")
    with tempfile.TemporaryDirectory(prefix="zbt-program-smoke-") as base:
        target, feed = fixture(base)
        code_p, hits_p, doc_p = scan([program], base, "program", target, feed)
        code_s, hits_s, _ = scan([sys.executable, "-X", "utf8", single], base, "single", target, feed)
        print("program exit {} hits {}".format(code_p, hits_p))
        print("single  exit {} hits {}".format(code_s, hits_s))
        indicators = {i for i, _e in hits_p}
        problems = []
        if DOMAIN not in indicators:
            problems.append("the planted history visit was not found")
        if hashlib.sha256(PAYLOAD).hexdigest() not in indicators:
            problems.append("the planted file fingerprint was not found")
        if hits_p != hits_s or code_p != code_s:
            problems.append("program and single-file results differ")
        version = str(doc_p.get("tool", "")) + str(doc_p.get("version", ""))
        if problems:
            sys.exit("FAIL: " + "; ".join(problems))
        print("PASS: program and single-file build agree ({})".format(version[:80]))


if __name__ == "__main__":
    main()
