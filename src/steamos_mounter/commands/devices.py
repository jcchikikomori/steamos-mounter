"""What ``add``, ``remove``, ``mount`` and ``unmount`` share: finding the device,
reading the registry, and naming the instance that owns a volume.

Design Doc "CLI Contract > Commands" (``--device`` canonicalized with
``realpath``, ``--uuid`` exact, duplicate UUIDs refused), "Locks" (I007: the
record key follows the instance, the lock key the volume) and ADR-0001's CLI
rules (a registered volume is served by its registered instance, an auto
volume by the auto instance of its physical partition).

A volume's owner is a ``reconcile_report.Owner``, the same value reconcile
builds, so the CLI writes the record and takes the lock reconcile uses.
"""

import os
from typing import TYPE_CHECKING, Final

from steamos_mounter import blockdev, config, systemd
from steamos_mounter.blockdev import KNAME_RE, BlockDevice, DeviceTree
from steamos_mounter.errors import (
    NotPresentError,
    RefusedError,
    RegistryError,
    UsageError,
)
from steamos_mounter.escape import auto_instance, registered_instance, unit_name
from steamos_mounter.locks import VOLUME_KEY
from steamos_mounter.model import InstanceKind, Registry, Volume
from steamos_mounter.naming import fallback_name, sanitize_label
from steamos_mounter.reconcile_report import Owner, record_key
from steamos_mounter.routing import AUTO_TEMPLATE, REGISTERED_TEMPLATE

if TYPE_CHECKING:
    from steamos_mounter.context import Context

CLI_LOCK_WAIT: Final = 30.0  # Design Doc "Locks": the CLI waits 30 s for a volume
UNIT_PROPERTIES: Final = ("LoadState", "ActiveState")
# A start would queue behind these; a reload reaches the running instance.
RUNNING_STATES: Final = frozenset({"active", "activating", "reloading"})
DUPLICATE_UUID: Final = "two devices share this UUID; unplug one"


def load_registry(ctx: "Context") -> Registry:
    """``config.load``; an unusable registry stops the command (exit 1)."""
    try:
        return config.load(ctx)
    except RegistryError as error:
        raise RegistryError(
            f"the registry cannot be used. Fix it first: run "
            f"{ctx.platform.cli_root} doctor",
            detail=error.detail,
        ) from error


def registered(registry: Registry, name: str) -> Volume:
    """The volume called ``name``; an unknown name is a usage error (exit 2)."""
    volume = registry.by_name(name)
    if volume is None:
        raise UsageError(f"no registered volume is called {name}")
    return volume


def device_kname(ctx: "Context", device: str) -> str:
    """The kernel name ``device`` resolves to with ``realpath`` (``/dev/<kname>``)."""
    if not device.startswith("/"):
        raise UsageError(f"{device} is not an absolute device path")
    resolved = os.path.realpath(ctx.paths.p(device))
    directory, _, kname = resolved.rpartition("/")
    if directory != os.path.realpath(ctx.paths.p("/dev")) or not KNAME_RE.fullmatch(
        kname
    ):
        raise UsageError(f"{device} is not a block device under /dev")
    return kname


def find_device(ctx: "Context", tree: DeviceTree, device: str) -> BlockDevice:
    """The tree's device for ``--device``; not attached is exit 7."""
    found = tree.devices.get(device_kname(ctx, device))
    if found is None:
        raise NotPresentError(f"{device} is not attached")
    return found


def find_uuid(tree: DeviceTree, uuid: str) -> BlockDevice:
    """The one device whose UUID is exactly ``uuid`` (exit 7 when none)."""
    found = [device for device in tree.devices.values() if device.uuid == uuid]
    if not found:
        raise NotPresentError(f"no attached device has the UUID {uuid}")
    require_unique(tree, found[0])
    return found[0]


def require_unique(tree: DeviceTree, device: BlockDevice) -> None:
    """Refuse a device whose UUID another attached device has too (exit 8)."""
    if device.uuid is not None and len(tree.by_uuid(device.uuid)) > 1:
        raise RefusedError(
            DUPLICATE_UUID, detail=f"{device.uuid} is on more than one device"
        )


def stacked_on(tree: DeviceTree, device: BlockDevice) -> tuple[BlockDevice, ...]:
    """The devices that sit directly on ``device`` (a container's mapping)."""
    return tuple(
        tree.devices[kname]
        for kname, parents in tree.parents.items()
        if device.kname in parents
    )


def registered_owner(volume: Volume, device: BlockDevice | None) -> Owner:
    """The registered instance of ``volume``: record and lock key are its UUID."""
    key = volume.uuid.lower()
    return Owner(
        kind=InstanceKind.REGISTERED,
        key=key,
        lock_key=key,
        name=volume.name,
        uuid=volume.uuid,
        unit=unit_name(REGISTERED_TEMPLATE, registered_instance(volume.uuid)),
        device=f"/dev/{device.kname}" if device is not None else "",
    )


def auto_owner(ctx: "Context", device: BlockDevice) -> Owner:
    """The auto instance of the physical partition (or container) ``device``."""
    syspath = blockdev.syspath(ctx, device.kname)
    if syspath is None:
        raise NotPresentError(f"/dev/{device.kname} is not attached")
    key = record_key(device)
    uuid = device.uuid or ""
    lowered = uuid.lower()
    return Owner(
        kind=InstanceKind.AUTO,
        key=key,
        lock_key=lowered if VOLUME_KEY.fullmatch(lowered) else key,
        name=sanitize_label(device.label)
        or fallback_name(device.fstype, device.uuid, device.kname),
        uuid=uuid,
        unit=unit_name(AUTO_TEMPLATE, auto_instance(syspath)),
        device=f"/dev/{device.kname}",
    )


def active_state(ctx: "Context", unit: str) -> str:
    """``ActiveState`` of ``unit``; a unit systemd does not know is ``inactive``."""
    properties = systemd.show(ctx, unit, UNIT_PROPERTIES)
    if not systemd.unit_exists(properties):
        return "inactive"
    return properties.get("ActiveState", "")
