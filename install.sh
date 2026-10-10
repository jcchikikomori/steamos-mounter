#!/bin/sh
# steamos-mounter installer and updater: stage a root-owned release under
# /opt/steamos-mounter/releases/ and hand over to that copy's Python installer.
#
#   sudo ./install.sh [--no-start]
#
# Non-interactive and idempotent: running it again is the update. Works from
# any checkout path; nothing installed refers to the checkout. Exit codes:
# 0 ok, 2 usage, 3 needs root, 4 unsupported platform, 5 partial (run it
# again). Every line starts with "steamos-mounter install:". No Python runs
# from the checkout as root (DD-24).
set -eu
umask 022

PREFIX='steamos-mounter install:'
OPT=/opt/steamos-mounter
PYTHON=/usr/bin/python3

say() {
    printf '%s %s\n' "$PREFIX" "$1"
}

fail() {
    say "$2"
    exit "$1"
}

# Run "$@"; on failure print its output prefixed, then exit 5.
step() {
    what=$1
    shift
    if ! output=$("$@" 2>&1); then
        printf '%s\n' "$output" | while IFS= read -r line; do
            say "$what: $line"
        done
        fail 5 "$what: failed: run install.sh again"
    fi
}

no_start=no
bad_option=no
for arg in "$@"; do
    case $arg in
        --no-start) no_start=yes ;;
        -h | --help)
            say "usage: sudo ./install.sh [--no-start]"
            say "installs or updates steamos-mounter under $OPT"
            exit 0
            ;;
        *) bad_option=yes ;;
    esac
done

# 1. The checkout, wherever it is.
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)

# 2. Platform, before anything else (AC-051, DD-30).
if ! grep -Eq '^ID="?steamos"?$' /etc/os-release 2>/dev/null; then
    fail 4 "unsupported platform: SteamOS only"
fi
if [ "$bad_option" = yes ]; then
    fail 2 "unknown option. Usage: sudo ./install.sh [--no-start]"
fi

# 3. Root (AC-066).
if [ "$(id -u)" -ne 0 ]; then
    fail 3 "needs root: run it with sudo"
fi

# 4. Python 3.11 or later at the path the units use.
if ! "$PYTHON" -I -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
    >/dev/null 2>&1; then
    fail 4 "needs Python 3.11 or later at $PYTHON"
fi

# 5. The version this checkout carries.
version=$(sed -n 's/^__version__ = "\([0-9A-Za-z.+-]*\)"$/\1/p' \
    "$here/src/steamos_mounter/__init__.py" 2>/dev/null) || version=''
if [ -z "$version" ]; then
    fail 5 "cannot read the version from src/steamos_mounter/__init__.py"
fi

# 6. A fresh release directory; mkdir fails if it exists already.
rel="$OPT/releases/$version-$(date -u +%Y%m%dT%H%M%SZ)"
step "stage" mkdir -p "$OPT/releases"
step "stage" chmod 0755 "$OPT" "$OPT/releases"
step "stage" mkdir "$rel"

# 7. The payload, root-owned, dirs 0755, files 0644, the entry point 0755.
step "copy" cp -R -P "$here/bin" "$here/data" "$here/README.md" "$rel/"
step "copy" mkdir "$rel/lib"
step "copy" cp -R -P "$here/src/steamos_mounter" "$rel/lib/"
step "copy" find "$rel" -name __pycache__ -type d -prune -exec rm -rf {} +
step "owner" chown -R 0:0 "$rel"
step "modes" find "$rel" -type d -exec chmod 0755 {} +
step "modes" find "$rel" -type f -exec chmod 0644 {} +
step "modes" chmod 0755 "$rel/bin/steamos-mounter"
say "stage: ok: $rel"

# 8. Hand over to the staged copy; stdin is never read.
set -- install --release "$rel"
if [ "$no_start" = yes ]; then
    set -- "$@" --no-start
fi
exec "$PYTHON" -I "$rel/bin/steamos-mounter" "$@" </dev/null
