"""Enums and value types shared by every module.

Design Doc "model, context, platforms". Enum values are the spellings the
registry, the runtime records and the journal use, so ``str(member)`` can be
written out as is. Every dataclass is frozen: a registry or a mount table read
once is never edited in place.
"""

from dataclasses import dataclass
from enum import StrEnum


class Mode(StrEnum):
    RW = "rw"
    RO = "ro"


class Driver(StrEnum):
    NTFS3 = "ntfs3"
    NTFS3G = "ntfs-3g"
    NTFS = "ntfs"
    EXFAT = "exfat"
    VFAT = "vfat"
    BTRFS = "btrfs"


@dataclass(frozen=True, slots=True)
class Step:
    """One attempt of a driver chain: a driver and the mode it mounts with."""

    driver: Driver
    mode: Mode


class InstanceKind(StrEnum):
    REGISTERED = "registered"
    AUTO = "auto"


class Trigger(StrEnum):
    START = "start"
    RELOAD = "reload"
    CLI = "cli"  # a reload that carries a fresh cli_request


class VolumeState(StrEnum):
    NOT_PRESENT = "NotPresent"
    NOT_MOUNTED = "NotMounted"
    LOCKED = "Locked"
    NEEDS_KEY = "NeedsKey"
    UNLOCK_FAILED = "UnlockFailed"
    UNLOCK_CANCELLED = "UnlockCancelled"
    MOUNTING = "Mounting"
    MOUNTED_RW = "MountedRW"
    MOUNTED_RW_DIRTY = "MountedRWDirty"
    MOUNTED_RO = "MountedRO"
    MOUNTED_ELSEWHERE = "MountedElsewhere"
    MOUNT_FAILED = "MountFailed"
    MOUNT_TIMED_OUT = "MountTimedOut"
    UNMOUNTED_BY_USER = "UnmountedByUser"


@dataclass(frozen=True, slots=True)
class Volume:
    """One valid registry entry. ``drivers`` None means the default chain."""

    name: str
    uuid: str
    path: str
    fstype: str
    drivers: tuple[Step, ...] | None
    nosuid: bool
    nodev: bool


@dataclass(frozen=True, slots=True)
class InvalidEntry:
    """A registry entry that failed validation; its UUID still blocks auto-mount."""

    index: int
    uuid: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class Registry:
    schema_version: int
    volumes: tuple[Volume, ...]
    invalid: tuple[InvalidEntry, ...]

    def by_uuid(self, uuid: str) -> Volume | None:
        """The volume with ``uuid``, compared case-insensitively."""
        wanted = uuid.lower()
        return next((v for v in self.volumes if v.uuid.lower() == wanted), None)

    def by_name(self, name: str) -> Volume | None:
        """The volume called ``name``, compared case-insensitively."""
        wanted = name.casefold()
        return next((v for v in self.volumes if v.name.casefold() == wanted), None)

    def blocked_uuids(self) -> frozenset[str]:
        """Lowercased UUIDs of valid and invalid entries: never auto-mounted."""
        valid = {volume.uuid.lower() for volume in self.volumes}
        invalid = {entry.uuid.lower() for entry in self.invalid if entry.uuid}
        return frozenset(valid | invalid)


@dataclass(frozen=True, slots=True)
class MountInfo:
    """One ``findmnt`` row. Options are split on commas, in their listed order."""

    target: str
    source: str
    fstype: str
    vfs_options: tuple[str, ...]
    fs_options: tuple[str, ...]
    devnum: str | None

    @property
    def read_only(self) -> bool:
        """True when either option list holds the exact option ``ro``."""
        return "ro" in self.vfs_options or "ro" in self.fs_options
