#!/bin/sh
# Build the Stage A scratch NTFS images (dev only, run in the Docker dev image).
#
# Usage: make_scratch_images.sh OUTPUT_DIR
#
# Writes three 64 MiB images into OUTPUT_DIR, which must already exist:
#   clean.img   a fresh mkntfs volume
#   dirty.img   VOLUME_IS_DIRTY set in $Volume (tools/ntfs_set_dirty.py)
#   unsafe.img  a hiberfil.sys that starts with "hibr" (Windows hibernated)
# Each image is its own mkntfs run with a fresh random serial (ntfslabel), so
# no two images share a /dev/disk/by-uuid name: mkntfs alone seeds the serial
# from the clock and gives all three the same one.
#
# NFR-15: refuses an OUTPUT_DIR under /dev (as given or once symlinks are
# resolved) and anything that is not a directory, and never touches an
# existing file: it only writes regular files it created itself.
#
# Exit codes: 0 built, 2 usage or refused (nothing written), other: a tool
# failed (the files this run created are removed).
set -eu

PROG=make_scratch_images.sh
MKNTFS=/usr/sbin/mkntfs
NTFSCP=/usr/sbin/ntfscp
NTFSLABEL=/usr/sbin/ntfslabel
IMAGE_SIZE=64M
HIBERFIL_HEADER_SIZE=4096
EXIT_REFUSED=2

refuse() {
    printf '%s: refused: %s\n' "$PROG" "$1" >&2
    exit "$EXIT_REFUSED"
}

refuse_dev_path() {
    case $1 in
        /dev | /dev/*) refuse "$1 is under /dev" ;;
    esac
}

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    printf 'usage: %s OUTPUT_DIR\n' "$PROG" >&2
    exit "$EXIT_REFUSED"
fi

given=$1
refuse_dev_path "$given"
if [ -b "$given" ]; then
    refuse "$given is a block device"
fi
if [ ! -d "$given" ]; then
    refuse "$given is not an existing directory"
fi
out=$(CDPATH='' cd -P -- "$given" && pwd -P) || refuse "cannot resolve $given"
refuse_dev_path "$out"

script_dir=$(CDPATH='' cd -P -- "$(dirname -- "$0")" && pwd -P)

clean=$out/clean.img
dirty=$out/dirty.img
unsafe=$out/unsafe.img
hiberfil=$out/hiberfil.sys.tmp
for target in "$clean" "$dirty" "$unsafe" "$hiberfil"; do
    if [ -e "$target" ] || [ -L "$target" ]; then
        refuse "$target already exists"
    fi
done

on_exit() {
    status=$?
    rm -f -- "$hiberfil"
    if [ "$status" -ne 0 ]; then
        rm -f -- "$clean" "$dirty" "$unsafe"
    fi
}
trap on_exit EXIT
trap 'exit 1' HUP INT TERM

# A new, empty regular file; noclobber makes the shell fail on a race.
create_file() {
    (set -C && : >"$1")
}

# The ntfs tools take no "--"; every path here is absolute (pwd -P), so none
# can be read as an option.
new_volume() {
    create_file "$1"
    truncate -s "$IMAGE_SIZE" -- "$1"
    "$MKNTFS" -F -Q -q "$1"
    "$NTFSLABEL" --new-serial "$1" >/dev/null
}

new_volume "$clean"

new_volume "$dirty"
python3 "$script_dir/ntfs_set_dirty.py" "$dirty"

new_volume "$unsafe"
create_file "$hiberfil"
{
    printf 'hibr'
    dd if=/dev/zero bs=$((HIBERFIL_HEADER_SIZE - 4)) count=1 2>/dev/null
} >>"$hiberfil"
"$NTFSCP" "$unsafe" "$hiberfil" hiberfil.sys

printf '%s: built clean.img, dirty.img and unsafe.img in %s\n' "$PROG" "$out"
