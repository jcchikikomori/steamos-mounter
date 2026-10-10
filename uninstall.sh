#!/bin/sh
# steamos-mounter uninstaller: run the installed copy's uninstall.
#
#   sudo ./uninstall.sh [--purge]
#
# Without --purge the registry is kept as
# /var/lib/steamos-mounter/kept-config.toml and the keys stay. When no
# installed copy is left, this script removes nothing itself: it reads this
# checkout's data/manifest.tsv only to list /etc leftovers (exit 5), or says
# "nothing to remove" (exit 0) (D012). Exit codes: 0 ok, 2 usage, 3 needs
# root, 4 unsupported platform, 5 partial (run it again), 6 done but busy.
# Every line starts with "steamos-mounter uninstall:".
set -eu
umask 022

PREFIX='steamos-mounter uninstall:'
PYTHON=/usr/bin/python3
INSTALLED=/opt/steamos-mounter/bin/steamos-mounter

say() {
    printf '%s %s\n' "$PREFIX" "$1"
}

fail() {
    say "$2"
    exit "$1"
}

purge=no
bad_option=no
for arg in "$@"; do
    case $arg in
        --purge) purge=yes ;;
        -h | --help)
            say "usage: sudo ./uninstall.sh [--purge]"
            say "--purge also deletes the registry and the keys"
            exit 0
            ;;
        *) bad_option=yes ;;
    esac
done

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)

# Platform, then the usage error, then root (AC-051, AC-066, DD-30).
if ! grep -Eq '^ID="?steamos"?$' /etc/os-release 2>/dev/null; then
    fail 4 "unsupported platform: SteamOS only"
fi
if [ "$bad_option" = yes ]; then
    fail 2 "unknown option. Usage: sudo ./uninstall.sh [--purge]"
fi
if [ "$(id -u)" -ne 0 ]; then
    fail 3 "needs root: run it with sudo"
fi

if [ -x "$INSTALLED" ]; then
    set -- uninstall
    if [ "$purge" = yes ]; then
        set -- "$@" --purge
    fi
    exec "$PYTHON" -I "$INSTALLED" "$@" </dev/null
fi

# No installed copy: list what the manifest says may be left in /etc.
manifest="$here/data/manifest.tsv"
if [ ! -r "$manifest" ]; then
    fail 5 "cannot read data/manifest.tsv in this checkout"
fi
leftovers=no
while read -r kind path _rest; do
    case $kind in
        file | registry) ;;
        *) continue ;;
    esac
    case $path in
        /etc/*) ;;
        *) continue ;;
    esac
    if [ -e "$path" ] || [ -L "$path" ]; then
        say "left over: $path"
        leftovers=yes
    fi
done <"$manifest"
if [ "$leftovers" = yes ]; then
    fail 5 "run ./install.sh, then this script again"
fi
say "nothing to remove"
