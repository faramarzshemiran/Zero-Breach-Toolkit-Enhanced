"""Prepare and sign a release, as described in docs/VERIFYING.md.

Builds the single-file scanner twice (the build must be reproducible), writes
release/<version>/ with the scanner, the release key's public half and a
SHA256SUMS.txt manifest, then signs the manifest and the scanner with the
release key through the local GnuPG keyring (gpg asks for the passphrase
itself; nothing here reads or stores it). Finally it verifies every signature
with a separate, temporary keyring that holds only the public key, and checks
that a modified copy is rejected.

It publishes nothing: uploading the folder to a GitHub release is a separate,
deliberate step. Usage:

    python tools/make_release.py            # build, sign, verify
    python tools/make_release.py --no-sign  # build and checksum only
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELEASE_KEY = "C24EC92B12D6670A2516065F9B4D575499AFA53C"
SCANNER = "zero-breach-toolkit.py"
PUBLIC_KEY = "archivegenocide-signing-key.asc"


def version():
    scope = {}
    with open(os.path.join(ROOT, "scan", "zbtriage", "__init__.py"), encoding="utf-8") as fh:
        exec(compile(fh.read(), "__init__.py", "exec"), scope)  # module only assigns constants
    return scope["__version__"]


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def gpg_home(path):
    """A keyring path in the form this platform's gpg understands. Git for
    Windows ships an MSYS gpg that reads only /c/... style paths."""
    exe = shutil.which("gpg") or ""
    if os.name == "nt" and os.sep + "usr" + os.sep + "bin" + os.sep in exe.lower():
        drive, rest = os.path.splitdrive(os.path.abspath(path))
        return "/" + drive.rstrip(":").lower() + rest.replace(os.sep, "/")
    return path


def gpg(args, home=None, batch=True, **kw):
    prefix = (["--batch"] if batch else []) + (["--homedir", gpg_home(home)] if home else [])
    return subprocess.run(["gpg"] + prefix + args, check=True, **kw)


def build(out_dir):
    first, second = (os.path.join(out_dir, name) for name in ("build-1.py", "build-2.py"))
    for target in (first, second):
        subprocess.run([sys.executable, os.path.join(ROOT, "build", "bundle.py"), ROOT, target], check=True,
                       stdout=subprocess.DEVNULL)
    if sha256(first) != sha256(second):
        raise SystemExit("the single-file build is not reproducible; refusing to release")
    os.replace(first, os.path.join(out_dir, SCANNER))
    os.remove(second)


def git(*args):
    return subprocess.run(["git"] + list(args), cwd=ROOT, check=True, capture_output=True,
                          text=True).stdout.strip()


def refuse_unless_releasable(tag):
    """The build reads the working tree, so it must be exactly a pushed commit:
    no uncommitted changes, HEAD on origin/main, and the version tag (if it
    already exists) on HEAD."""
    if git("status", "--porcelain"):
        raise SystemExit("refusing to build a release: the working tree has uncommitted changes")
    head = git("rev-parse", "HEAD")
    git("fetch", "--quiet", "origin", "main")
    if subprocess.run(["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"],
                      cwd=ROOT).returncode != 0:
        raise SystemExit("refusing to build a release: HEAD is not on origin/main")
    if git("tag", "--list", tag) and git("rev-list", "-n", "1", tag) != head:
        raise SystemExit("refusing to build a release: tag {} is not on HEAD".format(tag))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-sign", action="store_true", help="build and checksum only")
    parser.add_argument("--key", default=RELEASE_KEY, help="signing key fingerprint")
    parser.add_argument("--gnupg-home", help="keyring holding the signing key (default: gpg's own)")
    args = parser.parse_args()

    refuse_unless_releasable("v" + version())
    out = os.path.join(ROOT, "release", "v" + version())
    if os.path.exists(out):
        raise SystemExit("{} already exists; remove it deliberately before rebuilding".format(out))
    os.makedirs(out)
    build(out)
    files = [SCANNER]
    if not args.no_sign:
        with open(os.path.join(out, PUBLIC_KEY), "wb") as fh:
            fh.write(gpg(["--armor", "--export", args.key], home=args.gnupg_home, stdout=subprocess.PIPE).stdout)
        files.append(PUBLIC_KEY)
    with open(os.path.join(out, "SHA256SUMS.txt"), "w", encoding="ascii", newline="\n") as fh:
        for name in files:
            fh.write("{}  {}\n".format(sha256(os.path.join(out, name)), name))
    if args.no_sign:
        print("built", out)
        return 0

    for name in ("SHA256SUMS.txt", SCANNER):
        # Not batch: gpg asks for the key's passphrase itself.
        gpg(["--local-user", args.key, "--armor", "--detach-sign", "--output",
             os.path.join(out, name + ".asc"), os.path.join(out, name)], home=args.gnupg_home, batch=False)

    # Verify as a downloader would: a fresh keyring holding only the public key.
    with tempfile.TemporaryDirectory() as home:
        gpg(["--import", os.path.join(out, PUBLIC_KEY)], home=home, capture_output=True)
        listed = gpg(["--with-colons", "--fingerprint"], home=home, capture_output=True, text=True).stdout
        if "fpr:::::::::{}:".format(args.key) not in listed:
            raise SystemExit("exported public key does not carry the expected fingerprint")
        for name in ("SHA256SUMS.txt", SCANNER):
            gpg(["--verify", os.path.join(out, name + ".asc"), os.path.join(out, name)], home=home,
                capture_output=True)
        tampered = os.path.join(home, SCANNER)
        shutil.copyfile(os.path.join(out, SCANNER), tampered)
        with open(tampered, "ab") as fh:
            fh.write(b"\n# modified\n")
        bad = subprocess.run(["gpg", "--batch", "--homedir", gpg_home(home), "--verify",
                              os.path.join(out, SCANNER + ".asc"), tampered], capture_output=True)
        if bad.returncode == 0:
            raise SystemExit("a modified scanner verified; refusing this release")
    print("built, signed and verified", out)
    for name in sorted(os.listdir(out)):
        print("  ", name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
