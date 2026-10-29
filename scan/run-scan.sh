#!/bin/sh
# Terminal launcher for the source distribution on Linux and macOS.
set -eu
toolkit_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3 is required. Install Python, then run this launcher again.' >&2
    exit 1
fi
exec python3 "$toolkit_dir/zero-breach-toolkit.py" "$@"
