#!/usr/bin/env python3
"""Compare the old and new mount of one volume field by field (dev only, EVP-2).

Usage: compare_mounts.py OLD_FINDMNT OLD_STAT NEW_FINDMNT NEW_STAT

Each side is captured with:

    findmnt -J -o TARGET,SOURCE,FSTYPE,VFS-OPTIONS,FS-OPTIONS --mountpoint DIR
    stat -c '%U %G %a' DIR DIR/<file written by deck>

so a findmnt file holds exactly one filesystem and a stat file exactly two
lines: the mount root, then the ``deck``-written file. "Old" is the
old-behaviour baseline (a plain ``mount -t ntfs`` at a scratch target), "new"
the registered instance at its fixed path.

Prints one line per field of the Design Doc table (section "Output
Comparison"), each marked ``equal``, ``intended`` or ``UNEXPECTED``; an
UNEXPECTED line also names what was expected.

Exit codes: 0 every field equal or intended, 1 any field UNEXPECTED, 2 usage or
an unreadable capture (nothing compared).
"""

import json
import posixpath
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

PROG = "compare_mounts.py"
EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_USAGE = 2

EQUAL = "equal"
INTENDED = "intended"
UNEXPECTED = "UNEXPECTED"
STATUS_WIDTH = len(UNEXPECTED)

FINDMNT_KEYS = ("target", "source", "fstype", "vfs-options", "fs-options")
STAT_LINE = re.compile(r"(\S+) (\S+) ([0-7]{1,4})")
STAT_LINES = 2

DECK = "deck"
MOUNT_BASE = "/run/media/deck"
YES = "yes"
NO = "no"
NONE = "none"
# Per-mount flags that say nothing about safety: read-write is its own field and
# the access-time family is the kernel's choice.
NEUTRAL_VFS_OPTIONS = frozenset(
    {"rw", "ro", "relatime", "noatime", "strictatime", "nodiratime", "lazytime"}
)
OWNER_WRITE = 0o200
GROUP_WRITE = 0o020
OTHER_WRITE = 0o002


class CaptureError(Exception):
    """A capture file is missing or does not have the expected shape."""


@dataclass(frozen=True)
class StatLine:
    """One ``stat -c '%U %G %a'`` line."""

    user: str
    group: str
    mode: str

    @property
    def owner(self) -> str:
        return f"{self.user}:{self.group}"


@dataclass(frozen=True)
class Capture:
    """One side: the findmnt filesystem and the two stat lines."""

    mount: dict[str, str]
    root: StatLine
    file: StatLine


@dataclass(frozen=True)
class Expect:
    """What a field must read on one side: printable text and the test."""

    text: str
    accepts: Callable[[str], bool]


def exactly(value: str) -> Expect:
    return Expect(value, lambda observed: observed == value)


def same_options(*options: str) -> Expect:
    wanted = frozenset(options)
    text = ",".join(options) if options else NONE
    return Expect(text, lambda observed: _option_set(observed) == wanted)


def _option_set(observed: str) -> frozenset[str]:
    return frozenset() if observed == NONE else frozenset(observed.split(","))


def _is_base_child(path: str) -> bool:
    """A direct child of the mount base (fixed-path rule 9, DD-34)."""
    return posixpath.dirname(path) == MOUNT_BASE and posixpath.basename(path) != ""


ANY_TARGET = Expect("any scratch target", posixpath.isabs)
BASE_CHILD = Expect(f"{MOUNT_BASE}/<NAME>", _is_base_child)


# --- field readers ---------------------------------------------------------


def _options(capture: Capture, key: str) -> list[str]:
    return capture.mount[key].split(",")


def read_fstype(capture: Capture) -> str:
    return capture.mount["fstype"]


def read_write(capture: Capture) -> str:
    writable = "rw" in _options(capture, "vfs-options") and "ro" not in _options(
        capture, "fs-options"
    )
    return YES if writable else NO


def read_vfs_flags(capture: Capture) -> str:
    """The per-mount flags that matter, in capture order (``none`` if empty)."""
    flags = [
        option
        for option in _options(capture, "vfs-options")
        if option not in NEUTRAL_VFS_OPTIONS
    ]
    return ",".join(flags) if flags else NONE


def read_owner(capture: Capture) -> str:
    return f"{capture.root.owner} {capture.file.owner}"


def read_mode(capture: Capture) -> str:
    return f"{capture.root.mode} {capture.file.mode}"


def read_deck_creates(capture: Capture) -> str:
    """Whether ``deck`` may create entries in the mount root, from its stat line."""
    root = capture.root
    mode = int(root.mode, 8)
    writable = (
        (root.user == DECK and mode & OWNER_WRITE)
        or (root.group == DECK and mode & GROUP_WRITE)
        or mode & OTHER_WRITE
    )
    return YES if writable else NO


def read_target(capture: Capture) -> str:
    return capture.mount["target"]


# --- the Design Doc table --------------------------------------------------


@dataclass(frozen=True)
class Field:
    """One row of the Design Doc's expected-field table."""

    name: str
    read: Callable[[Capture], str]
    old: Expect
    new: Expect


# Mirrors "Output Comparison" in docs/design/steamos-mounter-design.md, with the
# new side's options and ownership from "Mount Options per Driver" (ntfs-3g rw:
# nosuid,nodev,uid=1000,gid=1000,umask=0022; never noexec). The status column is
# derived: both sides as expected and identical -> equal, as expected but
# different -> intended, anything else -> UNEXPECTED.
FIELDS: tuple[Field, ...] = (
    Field("fstype", read_fstype, exactly("fuseblk"), exactly("fuseblk")),
    Field("read-write", read_write, exactly(YES), exactly(YES)),
    Field(
        "vfs-options contains nosuid,nodev",
        read_vfs_flags,
        same_options(),
        same_options("nosuid", "nodev"),
    ),
    Field(
        "file owner",
        read_owner,
        exactly("root:root root:root"),
        exactly("deck:deck deck:deck"),
    ),
    Field("file mode", read_mode, exactly("777 777"), exactly("755 644")),
    Field("deck can create a file", read_deck_creates, exactly(YES), exactly(YES)),
    Field("target", read_target, ANY_TARGET, BASE_CHILD),
)


def compare(field: Field, old: Capture, new: Capture) -> str:
    """The report line for one field."""
    old_value = field.read(old)
    new_value = field.read(new)
    observed = f"{field.name}: old={old_value} new={new_value}"
    if not (field.old.accepts(old_value) and field.new.accepts(new_value)):
        expected = f"(expected old={field.old.text} new={field.new.text})"
        return f"{UNEXPECTED:<{STATUS_WIDTH}} {observed} {expected}"
    status = EQUAL if old_value == new_value else INTENDED
    return f"{status:<{STATUS_WIDTH}} {observed}"


# --- capture parsing -------------------------------------------------------


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise CaptureError(f"{path}: {error}") from error


def parse_findmnt(path: Path) -> dict[str, str]:
    """The single filesystem of a ``findmnt -J`` capture."""
    try:
        document = json.loads(_read_text(path))
    except json.JSONDecodeError as error:
        raise CaptureError(f"{path}: not JSON: {error}") from error
    filesystems = document.get("filesystems") if isinstance(document, dict) else None
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise CaptureError(f"{path}: expected exactly one filesystem")
    mount = filesystems[0]
    if not isinstance(mount, dict):
        raise CaptureError(f"{path}: the filesystem is not an object")
    for key in FINDMNT_KEYS:
        if not isinstance(mount.get(key), str):
            raise CaptureError(f"{path}: no string {key!r} column")
    return {key: mount[key] for key in FINDMNT_KEYS}


def parse_stat(path: Path) -> tuple[StatLine, StatLine]:
    """The mount root and file lines of a ``stat -c '%U %G %a'`` capture."""
    lines = _read_text(path).splitlines()
    if len(lines) != STAT_LINES:
        raise CaptureError(f"{path}: expected {STAT_LINES} stat lines")
    parsed = []
    for line in lines:
        match = STAT_LINE.fullmatch(line.strip())
        if match is None:
            raise CaptureError(f"{path}: not a '%U %G %a' line: {line!r}")
        parsed.append(StatLine(*match.groups()))
    return parsed[0], parsed[1]


def load_capture(findmnt_path: Path, stat_path: Path) -> Capture:
    root, file = parse_stat(stat_path)
    return Capture(parse_findmnt(findmnt_path), root, file)


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            f"usage: {PROG} OLD_FINDMNT OLD_STAT NEW_FINDMNT NEW_STAT", file=sys.stderr
        )
        return EXIT_USAGE
    old_findmnt, old_stat, new_findmnt, new_stat = (Path(arg) for arg in argv)
    try:
        old = load_capture(old_findmnt, old_stat)
        new = load_capture(new_findmnt, new_stat)
    except CaptureError as error:
        print(f"{PROG}: {error}", file=sys.stderr)
        return EXIT_USAGE
    lines = [compare(field, old, new) for field in FIELDS]
    print("\n".join(lines))
    unexpected = any(line.startswith(UNEXPECTED) for line in lines)
    return EXIT_UNEXPECTED if unexpected else EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
