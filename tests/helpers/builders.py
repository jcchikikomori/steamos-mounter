"""Test data builders: registry text, record dicts and lsblk device trees.

Design Doc "Data Layer Testing Strategy": builders produce registries, records
and device trees for tests. They are written from the Design Doc's schemas
(sections "Registry (config.toml)", "Record Schema (Format 1)" and the lsblk
columns of ``blockdev``), not from the package, so a test that compares package
output with a builder checks the package against the schema. This module grows
in Phase 2.
"""

import copy
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

# --- registry (config.toml, schema version 1) ---------------------------------

REGISTRY_HEADER = (
    "# steamos-mounter registry. Managed by steamos-mounter: "
    "comments and formatting are not kept."
)
SCHEMA_VERSION_LINE = "schema_version = 1"
TOML_ESCAPES = {'"': '\\"', "\\": "\\\\"}
DELETE = "\x7f"
FIRST_PRINTABLE = " "


@dataclass(frozen=True, slots=True)
class RegistryVolume:
    """One ``[[volume]]`` table; ``drivers`` is written only when set."""

    name: str
    uuid: str
    path: str
    fstype: str
    drivers: tuple[str, ...] | None = None
    nosuid: bool = True
    nodev: bool = True


MEDIABOX = RegistryVolume(
    name="MEDIABOX",
    uuid="01D95F1575592A30",
    path="/run/media/deck/MEDIABOX",
    fstype="ntfs",
)
PERSONAL = RegistryVolume(
    name="PERSONAL",
    uuid="658207d5-5177-4a52-a297-31643c64724d",
    path="/run/media/deck/PERSONAL",
    fstype="BitLocker",
    drivers=("ntfs3", "ntfs-3g", "ntfs3:ro"),
)


def toml_string(value: str) -> str:
    """TOML basic string with ``\\\\``, ``\\"`` and ``\\uXXXX`` escapes."""
    escaped = []
    for char in value:
        if char in TOML_ESCAPES:
            escaped.append(TOML_ESCAPES[char])
        elif char < FIRST_PRINTABLE or char == DELETE:
            escaped.append(f"\\u{ord(char):04X}")
        else:
            escaped.append(char)
    return '"' + "".join(escaped) + '"'


def toml_bool(value: bool) -> str:
    return "true" if value else "false"


def volume_table(volume: RegistryVolume) -> str:
    lines = [
        "[[volume]]",
        f"name = {toml_string(volume.name)}",
        f"uuid = {toml_string(volume.uuid)}",
        f"path = {toml_string(volume.path)}",
        f"fstype = {toml_string(volume.fstype)}",
    ]
    if volume.drivers is not None:
        drivers = ", ".join(toml_string(driver) for driver in volume.drivers)
        lines.append(f"drivers = [{drivers}]")
    lines.append(f"nosuid = {toml_bool(volume.nosuid)}")
    lines.append(f"nodev = {toml_bool(volume.nodev)}")
    return "\n".join(lines) + "\n"


def registry_text(volumes: Iterable[RegistryVolume]) -> str:
    """``config.toml`` text in the emitter's exact shape, volumes sorted by name."""
    head = f"{REGISTRY_HEADER}\n{SCHEMA_VERSION_LINE}\n"
    tables = [volume_table(volume) for volume in sorted(volumes, key=_volume_name)]
    return "\n".join([head, *tables])


def _volume_name(volume: RegistryVolume) -> str:
    return volume.name


# --- runtime state records (format 1) -----------------------------------------

# The Design Doc "Record Schema (Format 1)" example, field for field.
RECORD_EXAMPLE: dict[str, Any] = {
    "format": 1,
    "kind": "registered",
    "key": "658207d5-5177-4a52-a297-31643c64724d",
    "name": "PERSONAL",
    "unit": (
        "steamos-mounter@dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52"
        "\\x2da297\\x2d31643c64724d.service"
    ),
    "invocation_id": "0f6c9c1e5c7a4c51a0a5f3f3b2b6d7e8",
    "state": "MountedRWDirty",
    "reason": "dirty",
    "warning": (
        "PERSONAL is dirty: Windows did not close it cleanly. "
        "It is mounted read-write with ntfs-3g."
    ),
    "next_step": "Run chkdsk /f on it in Windows.",
    "updated_at": "2026-10-08T02:11:40Z",
    "trigger": "start",
    "source": {
        "kname": "sdb1",
        "devnum": "8:17",
        "syspath": "/sys/devices/pci0000:00/.../block/sdb/sdb1",
    },
    "mapping": {
        "name": "steamos-mounter-658207d5-5177-4a52-a297-31643c64724d",
        "kname": "dm-0",
        "devnum": "252:0",
        "opened_by": "handler",
        "key_unit_invocation_id": None,
        "save_pending": False,
    },
    "mount": {
        "status": "mounted",
        "target": "/run/media/deck/PERSONAL",
        "device": "/dev/dm-0",
        "devnum": "252:0",
        "driver": "ntfs-3g",
        "mode": "rw",
        "created_dir": True,
    },
    "attempt": {
        "probe": {"code": 0, "class": "safe"},
        "steps": [
            {
                "driver": "ntfs3",
                "mode": "rw",
                "result": "refused",
                "detail": 'volume is dirty and "force" flag is not set!',
            },
            {"driver": "ntfs-3g", "mode": "rw", "result": "mounted", "detail": ""},
        ],
        "skipped": [],
    },
    "unmounted_by_user": None,
    "cli_request": None,
    "dialog": {"outcome": None, "at": None},
    "service": {"result": None, "exit_code": None, "exit_status": None, "at": None},
    "busy": [],
}


def record_dict(**changes: Any) -> dict[str, Any]:
    """A fresh copy of the example record with top-level fields replaced.

    An unknown field name raises ``KeyError``, so a typo cannot slip into a
    record silently.
    """
    unknown = set(changes) - set(RECORD_EXAMPLE)
    if unknown:
        raise KeyError(f"not a record field: {', '.join(sorted(unknown))}")
    return copy.deepcopy(RECORD_EXAMPLE) | copy.deepcopy(changes)


# --- lsblk device trees (--json --bytes --tree) --------------------------------

# blockdev.LSBLK_COLUMNS, as lsblk spells the JSON keys.
LSBLK_KEYS = (
    "name",
    "kname",
    "path",
    "maj:min",
    "type",
    "fstype",
    "fsver",
    "label",
    "uuid",
    "ptuuid",
    "pttype",
    "partuuid",
    "partlabel",
    "parttypename",
    "pkname",
    "hotplug",
    "rm",
    "ro",
    "tran",
    "size",
    "mountpoints",
)
LSBLK_CHILDREN = "children"
LSBLK_BOOLEAN_KEYS = ("hotplug", "rm", "ro")


def lsblk_device(
    kname: str, columns: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """One lsblk JSON node; ``columns`` overrides defaults and may add children.

    Defaults: a partition named ``kname`` at ``/dev/<kname>``, size 0, not
    mounted, booleans false and every other column null. lsblk omits
    ``children`` when a device has none, and so does this builder.
    """
    columns = dict(columns or {})
    unknown = set(columns) - {*LSBLK_KEYS, LSBLK_CHILDREN}
    if unknown:
        raise KeyError(f"not an lsblk column: {', '.join(sorted(unknown))}")
    device: dict[str, Any] = dict.fromkeys(LSBLK_KEYS)
    device.update(dict.fromkeys(LSBLK_BOOLEAN_KEYS, False))
    device.update(name=kname, kname=kname, path=f"/dev/{kname}", type="part", size=0)
    device["mountpoints"] = []
    device.update(columns)
    return device


def lsblk_tree(devices: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """The top-level ``{"blockdevices": [...]}`` document."""
    return {"blockdevices": list(devices)}
