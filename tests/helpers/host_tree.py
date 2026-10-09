"""Fake sysfs and /dev/disk trees under a test root (``HostPaths(root=tmp_path)``).

Design Doc "Mock Boundary Decisions": sysfs is not mocked; tests read real files
and real symlinks under ``tmp_path``. The layout follows the kernel's:

- each device has one canonical directory (``syspath``) holding ``dev``,
  ``dm/name`` and other attribute files (one value plus a newline) and the
  ``slaves/`` and ``holders/`` directories;
- ``/sys/class/block/<kname>``, ``/sys/block/<kname>`` (whole disks and dm
  devices only, not partitions) and ``/sys/dev/block/<major>:<minor>`` are
  symlinks to it;
- a partition's directory sits inside its disk's directory.

Every symlink is relative, so a resolved path stays inside the root.
``parse_sysfs_facts`` turns the Deck capture ``sysfs-facts.txt`` into devices.
"""

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from tests.helpers.fixtures import load_fixture

SYSFS_FACTS = "sysfs-facts.txt"
CLASS_BLOCK = "/sys/class/block"
SYS_BLOCK = "/sys/block"
DEV_BLOCK = "/sys/dev/block"
VIRTUAL_BLOCK = "/sys/devices/virtual/block"
# Parent directory for physical disks that were given no syspath.
PHYSICAL_BLOCK = "/sys/devices/host-tree/block"
VIRTUAL_PREFIXES = ("dm-", "loop")

DEV_ATTRIBUTE = "dev"
DM_NAME_ATTRIBUTE = "dm/name"
PARTITION_ATTRIBUTE = "partition"
LISTING_ATTRIBUTES = ("slaves", "holders")

FACT_PATH = re.compile(
    r"/sys/(?:block|class/block)/(?P<kname>[^/=]+)/(?P<attribute>.+)"
)
# A partition of a disk whose name ends in a digit takes a "p" (mmcblk0p1).
PARTITION_NAME = re.compile(r"(?P<after_digit>.*\d)p\d+|(?P<plain>.*\D)\d+")


@dataclass(frozen=True, slots=True)
class SysfsDevice:
    """One block device as sysfs shows it.

    ``attributes`` maps a path relative to the device directory (for example
    ``"removable"`` or ``"dm/uuid"``) to its value without the trailing newline.
    """

    kname: str
    devnum: str | None = None
    parent: str | None = None
    syspath: str | None = None
    slaves: tuple[str, ...] = ()
    holders: tuple[str, ...] = ()
    dm_name: str | None = None
    attributes: Mapping[str, str] = field(default_factory=dict)


def partition_parent(kname: str) -> str:
    """Whole-disk kname of partition ``kname`` (``sdb5`` -> ``sdb``)."""
    match = PARTITION_NAME.fullmatch(kname)
    if match is None:
        raise ValueError(f"sysfs fact: cannot name the disk of partition {kname!r}")
    return match["after_digit"] or match["plain"]


def parse_sysfs_facts(text: str | None = None) -> tuple[SysfsDevice, ...]:
    """Devices described by ``path=value`` lines (default: the Deck capture).

    ``slaves`` and ``holders`` values are space-separated directory listings.
    A device with a ``partition`` attribute gets its disk as ``parent``.
    """
    if text is None:
        text = load_fixture(SYSFS_FACTS).decode("utf-8")
    facts: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        path, separator, value = line.partition("=")
        match = FACT_PATH.fullmatch(path)
        if not separator or match is None:
            raise ValueError(f"sysfs fact line not understood: {line!r}")
        facts.setdefault(match["kname"], {})[match["attribute"]] = value
    return tuple(_device_from_facts(kname, values) for kname, values in facts.items())


def _device_from_facts(kname: str, values: dict[str, str]) -> SysfsDevice:
    special = {DEV_ATTRIBUTE, DM_NAME_ATTRIBUTE, *LISTING_ATTRIBUTES}
    return SysfsDevice(
        kname=kname,
        devnum=values.get(DEV_ATTRIBUTE),
        parent=partition_parent(kname) if PARTITION_ATTRIBUTE in values else None,
        slaves=tuple(values.get("slaves", "").split()),
        holders=tuple(values.get("holders", "").split()),
        dm_name=values.get(DM_NAME_ATTRIBUTE),
        attributes={key: value for key, value in values.items() if key not in special},
    )


def _symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(os.path.relpath(target, link.parent))


def _write_value(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{value}\n", encoding="utf-8")


class HostTree:
    """Builds sysfs and ``/dev/disk`` entries under ``root``."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._syspaths: dict[str, str] = {}

    def path(self, absolute: str) -> Path:
        """``absolute`` mapped under the root, like ``HostPaths.p``."""
        return self.root / absolute.lstrip("/")

    def add_block(self, device: SysfsDevice) -> Path:
        """Create ``device`` and its links; return its canonical directory."""
        syspath = device.syspath or self._default_syspath(device)
        device_dir = self.path(syspath)
        device_dir.mkdir(parents=True, exist_ok=True)
        self._syspaths[device.kname] = syspath
        self._write_attributes(device_dir, device)
        self._write_listing(device_dir / "slaves", device.slaves)
        self._write_listing(device_dir / "holders", device.holders)
        _symlink(self.path(f"{CLASS_BLOCK}/{device.kname}"), device_dir)
        if device.parent is None:
            _symlink(self.path(f"{SYS_BLOCK}/{device.kname}"), device_dir)
        if device.devnum is not None:
            _symlink(self.path(f"{DEV_BLOCK}/{device.devnum}"), device_dir)
        return device_dir

    def add_sysfs_facts(self, text: str | None = None) -> tuple[SysfsDevice, ...]:
        """Add every device of ``parse_sysfs_facts(text)``, in file order."""
        devices = parse_sysfs_facts(text)
        for device in devices:
            self.add_block(device)
        return devices

    def link_by_uuid(self, uuid: str, kname: str) -> Path:
        """``/dev/disk/by-uuid/<uuid>`` -> ``../../<kname>``."""
        return self._device_link(f"/dev/disk/by-uuid/{uuid}", kname)

    def link_by_partsets(self, name: str, kname: str) -> Path:
        """``/dev/disk/by-partsets/all/<name>`` -> ``../../../<kname>``."""
        return self._device_link(f"/dev/disk/by-partsets/all/{name}", kname)

    def _default_syspath(self, device: SysfsDevice) -> str:
        if device.parent is not None:
            disk = self._syspaths.get(
                device.parent, f"{PHYSICAL_BLOCK}/{device.parent}"
            )
            return f"{disk}/{device.kname}"
        if device.kname.startswith(VIRTUAL_PREFIXES):
            return f"{VIRTUAL_BLOCK}/{device.kname}"
        return f"{PHYSICAL_BLOCK}/{device.kname}"

    def _write_attributes(self, device_dir: Path, device: SysfsDevice) -> None:
        values = dict(device.attributes)
        if device.devnum is not None:
            values[DEV_ATTRIBUTE] = device.devnum
        if device.dm_name is not None:
            values[DM_NAME_ATTRIBUTE] = device.dm_name
        for relative, value in values.items():
            _write_value(device_dir / relative, value)

    def _write_listing(self, directory: Path, knames: tuple[str, ...]) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        for kname in knames:
            _symlink(directory / kname, self.path(f"{CLASS_BLOCK}/{kname}"))

    def _device_link(self, link_path: str, kname: str) -> Path:
        # A device node cannot be made without root; an empty regular file
        # stands in for it so the link resolves and exists().
        node = self.path(f"/dev/{kname}")
        node.parent.mkdir(parents=True, exist_ok=True)
        node.touch(exist_ok=True)
        link = self.path(link_path)
        _symlink(link, node)
        return link
