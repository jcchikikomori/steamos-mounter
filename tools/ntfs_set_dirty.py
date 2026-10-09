#!/usr/bin/env python3
"""Set VOLUME_IS_DIRTY in an NTFS image file (dev only, Stage A scratch images).

Usage: ntfs_set_dirty.py IMAGE

Parses the boot sector, reads MFT record 3 (``$Volume``) from both ``$MFT``
and ``$MFTMirr``, and sets the dirty bit in the flags of the resident
``VOLUME_INFORMATION`` attribute in place. Both copies are written, because
ntfs-3g refuses a volume whose mirror does not match.

NFR-15: refuses a path under /dev (as given or once symlinks are resolved), a
block device and anything that is not a regular file. Never run it on a real
drive.

Exit codes: 0 flag set, 1 the file is not NTFS (nothing written), 2 usage or
refused (nothing written).
"""

import os
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

PROG = "ntfs_set_dirty.py"
EXIT_OK = 0
EXIT_NOT_NTFS = 1
EXIT_REFUSED = 2

DEV = Path("/dev")

# Boot sector (offsets from the start of the volume).
BOOT_SECTOR_SIZE = 512
OEM_ID_OFFSET = 0x03
OEM_ID = b"NTFS    "
BYTES_PER_SECTOR_OFFSET = 0x0B
SECTORS_PER_CLUSTER_OFFSET = 0x0D
MFT_LCN_OFFSET = 0x30
MFT_MIRROR_LCN_OFFSET = 0x38
CLUSTERS_PER_RECORD_OFFSET = 0x40
BOOT_SIGNATURE_OFFSET = 0x1FE
BOOT_SIGNATURE = b"\x55\xaa"
# Values above this in the sectors-per-cluster byte mean 2 ** (256 - value).
SECTORS_PER_CLUSTER_SHIFT_BASE = 0x80
MIN_SECTOR_SIZE = 256
MAX_SECTOR_SIZE = 4096
MIN_RECORD_SIZE = 256
MAX_RECORD_SIZE = 65536

# MFT record header.
VOLUME_RECORD = 3
RECORD_MAGIC = b"FILE"
USA_OFFSET_OFFSET = 0x04
USA_COUNT_OFFSET = 0x06
FIRST_ATTRIBUTE_OFFSET = 0x14
RECORD_FLAGS_OFFSET = 0x16
RECORD_IN_USE = 0x0001
# Update sequence fixups protect the last two bytes of every 512-byte block.
FIXUP_STRIDE = 512

# Attribute headers.
ATTRIBUTE_END = 0xFFFFFFFF
VOLUME_INFORMATION = 0x70
ATTRIBUTE_LENGTH_OFFSET = 0x04
NON_RESIDENT_OFFSET = 0x08
VALUE_LENGTH_OFFSET = 0x10
VALUE_OFFSET_OFFSET = 0x14
RESIDENT_HEADER_SIZE = 0x18
# VOLUME_INFORMATION value: 8 reserved bytes, major, minor, flags (u16).
VOLUME_FLAGS_OFFSET = 0x0A
VOLUME_INFORMATION_SIZE = 0x0C
VOLUME_IS_DIRTY = 0x0001


class NotNtfsError(Exception):
    """The file does not look like an NTFS volume this tool understands."""


@dataclass(frozen=True)
class Geometry:
    """Where the two copies of the ``$Volume`` record live, in bytes."""

    record_size: int
    mft_offset: int
    mirror_offset: int

    def volume_record_offsets(self) -> tuple[int, int]:
        skip = VOLUME_RECORD * self.record_size
        return self.mft_offset + skip, self.mirror_offset + skip


def refusal_reason(given: Path, resolved: Path, mode: int) -> str | None:
    """Why the target must not be written, or ``None`` when it may be."""
    for path in (given, resolved):
        if path == DEV or DEV in path.parents:
            return f"{path} is under /dev"
    if stat.S_ISBLK(mode):
        return "block device"
    if not stat.S_ISREG(mode):
        return "not a regular file"
    return None


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _is_power_of_two_between(value: int, low: int, high: int) -> bool:
    return low <= value <= high and value & (value - 1) == 0


def parse_boot_sector(boot: bytes) -> Geometry:
    """Record size and the byte offsets of ``$MFT`` and ``$MFTMirr``."""
    if len(boot) < BOOT_SECTOR_SIZE:
        raise NotNtfsError("shorter than a boot sector")
    if boot[OEM_ID_OFFSET : OEM_ID_OFFSET + len(OEM_ID)] != OEM_ID:
        raise NotNtfsError("no NTFS OEM ID in the boot sector")
    if boot[BOOT_SIGNATURE_OFFSET:BOOT_SECTOR_SIZE] != BOOT_SIGNATURE:
        raise NotNtfsError("no boot sector signature")
    sector_size = _u16(boot, BYTES_PER_SECTOR_OFFSET)
    if not _is_power_of_two_between(sector_size, MIN_SECTOR_SIZE, MAX_SECTOR_SIZE):
        raise NotNtfsError(f"bad bytes per sector {sector_size}")
    cluster_size = sector_size * _sectors_per_cluster(boot[SECTORS_PER_CLUSTER_OFFSET])
    record_size = _record_size(boot[CLUSTERS_PER_RECORD_OFFSET], cluster_size)
    mft_lcn = _u64(boot, MFT_LCN_OFFSET)
    mirror_lcn = _u64(boot, MFT_MIRROR_LCN_OFFSET)
    if mft_lcn == 0 or mirror_lcn == 0:
        raise NotNtfsError("no $MFT or $MFTMirr location")
    return Geometry(record_size, mft_lcn * cluster_size, mirror_lcn * cluster_size)


def _sectors_per_cluster(raw: int) -> int:
    if raw == 0:
        raise NotNtfsError("zero sectors per cluster")
    if raw > SECTORS_PER_CLUSTER_SHIFT_BASE:
        return 1 << (256 - raw)
    return raw


def _record_size(raw: int, cluster_size: int) -> int:
    """Decode the signed clusters-per-record byte (negative: 2 ** -value)."""
    signed = raw - 256 if raw > 127 else raw
    size = cluster_size * signed if signed > 0 else 1 << -signed
    if not _is_power_of_two_between(size, MIN_RECORD_SIZE, MAX_RECORD_SIZE):
        raise NotNtfsError(f"bad MFT record size {size}")
    return size


def remove_fixups(record: bytes) -> tuple[bytearray, int]:
    """The record with its protected bytes restored, and its sequence number."""
    if record[: len(RECORD_MAGIC)] != RECORD_MAGIC:
        raise NotNtfsError("$Volume record has no FILE magic")
    usa_offset = _u16(record, USA_OFFSET_OFFSET)
    usa_count = _u16(record, USA_COUNT_OFFSET)
    blocks = len(record) // FIXUP_STRIDE
    if usa_count != blocks + 1 or usa_offset + 2 * usa_count > len(record):
        raise NotNtfsError("$Volume record has a bad update sequence array")
    restored = bytearray(record)
    sequence = _u16(record, usa_offset)
    for block in range(blocks):
        end = (block + 1) * FIXUP_STRIDE - 2
        if _u16(record, end) != sequence:
            raise NotNtfsError("$Volume record fails its fixup check")
        saved = usa_offset + 2 * (block + 1)
        restored[end : end + 2] = record[saved : saved + 2]
    return restored, sequence


def apply_fixups(record: bytearray, sequence: int) -> bytes:
    """The on-disk form of ``record``: block ends saved and replaced."""
    usa_offset = _u16(record, USA_OFFSET_OFFSET)
    protected = bytearray(record)
    for block in range(len(record) // FIXUP_STRIDE):
        end = (block + 1) * FIXUP_STRIDE - 2
        saved = usa_offset + 2 * (block + 1)
        protected[saved : saved + 2] = record[end : end + 2]
        struct.pack_into("<H", protected, end, sequence)
    return bytes(protected)


def volume_flags_offset(record: bytes) -> int:
    """Offset of the VOLUME_INFORMATION flags inside a restored record."""
    if not _u16(record, RECORD_FLAGS_OFFSET) & RECORD_IN_USE:
        raise NotNtfsError("$Volume record is not in use")
    offset = _u16(record, FIRST_ATTRIBUTE_OFFSET)
    while offset + RESIDENT_HEADER_SIZE <= len(record):
        kind = _u32(record, offset)
        length = _u32(record, offset + ATTRIBUTE_LENGTH_OFFSET)
        if kind == ATTRIBUTE_END or length == 0:
            break
        if kind == VOLUME_INFORMATION:
            return _resident_flags_offset(record, offset, length)
        offset += length
    raise NotNtfsError("$Volume record has no VOLUME_INFORMATION attribute")


def _resident_flags_offset(record: bytes, attribute: int, length: int) -> int:
    if record[attribute + NON_RESIDENT_OFFSET] != 0:
        raise NotNtfsError("VOLUME_INFORMATION is not resident")
    value_length = _u32(record, attribute + VALUE_LENGTH_OFFSET)
    value_offset = _u16(record, attribute + VALUE_OFFSET_OFFSET)
    if (
        value_length < VOLUME_INFORMATION_SIZE
        or value_offset + VOLUME_INFORMATION_SIZE > length
        or attribute + length > len(record)
    ):
        raise NotNtfsError("VOLUME_INFORMATION has a bad size")
    return attribute + value_offset + VOLUME_FLAGS_OFFSET


def mark_dirty(record: bytes) -> bytes:
    """The on-disk ``$Volume`` record with VOLUME_IS_DIRTY set."""
    restored, sequence = remove_fixups(record)
    flags_at = volume_flags_offset(restored)
    flags = _u16(restored, flags_at) | VOLUME_IS_DIRTY
    struct.pack_into("<H", restored, flags_at, flags)
    return apply_fixups(restored, sequence)


def _read_exact(image: BinaryIO, offset: int, size: int) -> bytes:
    image.seek(offset)
    data = image.read(size)
    if len(data) != size:
        raise NotNtfsError(f"file ends before byte {offset + size}")
    return data


def set_dirty(image: BinaryIO) -> None:
    """Set the flag in ``$MFT`` and ``$MFTMirr``; write only if both parse."""
    boot = image.read(BOOT_SECTOR_SIZE)
    geometry = parse_boot_sector(boot)
    updates = [
        (offset, mark_dirty(_read_exact(image, offset, geometry.record_size)))
        for offset in geometry.volume_record_offsets()
    ]
    for offset, record in updates:
        image.seek(offset)
        image.write(record)


def _open_regular_file(given: Path) -> BinaryIO:
    """Open ``given`` for update, or raise ``PermissionError`` with the reason."""
    resolved = given.resolve()
    reason = refusal_reason(given.absolute(), resolved, _mode(resolved))
    if reason is not None:
        raise PermissionError(reason)
    descriptor = os.open(resolved, os.O_RDWR | os.O_NOFOLLOW)
    reason = refusal_reason(resolved, resolved, os.fstat(descriptor).st_mode)
    if reason is not None:
        os.close(descriptor)
        raise PermissionError(reason)
    return os.fdopen(descriptor, "r+b")


def _mode(path: Path) -> int:
    """The file type of ``path``; 0 (not a regular file) when it is missing."""
    try:
        return path.stat().st_mode
    except FileNotFoundError:
        return 0


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(f"usage: {PROG} IMAGE", file=sys.stderr)
        return EXIT_REFUSED
    given = Path(argv[0])
    try:
        image = _open_regular_file(given)
    except PermissionError as error:
        print(f"{PROG}: refused: {given}: {error}", file=sys.stderr)
        return EXIT_REFUSED
    with image:
        try:
            set_dirty(image)
        except NotNtfsError as error:
            print(f"{PROG}: not NTFS: {given}: {error}", file=sys.stderr)
            return EXIT_NOT_NTFS
    print(f"{PROG}: VOLUME_IS_DIRTY set in {given}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
