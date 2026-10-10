"""Whether a block device can be registered or mounted on request, and why not.

Design Doc "CLI Contract > Commands" (``scan`` reasons, ``add`` step 3,
``mount`` D013), DD-02 and DD-16. The reasons are the words ``scan`` prints
after ``no:``; ``add`` and ``mount --device`` refuse with the same words
(exit 8), so every reason text lives here and nowhere else.

The checks read one lsblk tree, the OS partition set and the registry, and
decide in this order:

1. an unusable registry (``scan`` keeps listing, D007);
2. a mapping (``crypt`` or ``dm-*``): register its container instead;
3. the OS partition set: unknown fails closed (DD-02), a member is refused;
4. the filesystem: none, ext4 (SteamOS handles it), or not registrable;
5. a UUID that is registered already.

Whole disks with a filesystem, internal non-OS partitions and loop devices
are registrable (AC-055, DD-16). ``mount --device`` of an unregistered
device uses steps 2 to 4 only; a mapping is mountable through its BitLocker
container.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from steamos_mounter import blockdev
from steamos_mounter.blockdev import BlockDevice, DeviceTree
from steamos_mounter.model import Registry
from steamos_mounter.platforms.base import OsPartitionSet
from steamos_mounter.routing import BITLOCKER, CRYPT_TYPE, DM_PREFIX, EXT4

if TYPE_CHECKING:
    from steamos_mounter.context import Context

REGISTRY_UNUSABLE: Final = "registry unusable"
MAPPING: Final = "unlocked mapping: register its container {container}"
MAPPING_WITHOUT_CONTAINER: Final = "unlocked mapping without a container"
OS_SET_UNREADABLE: Final = "OS partition list unreadable"
OS_PARTITION: Final = "OS partition"
NO_FILESYSTEM: Final = "no filesystem"
EXT4_HANDLED: Final = "ext4 (SteamOS handles it)"
UNSUPPORTED: Final = "unsupported type {fstype}"
REGISTERED: Final = "already registered as {name}"
REGISTERED_INVALID: Final = "already registered by an invalid registry entry"


@dataclass(frozen=True, slots=True)
class Facts:
    """One read of everything the decision needs; ``registry`` None = unusable."""

    tree: DeviceTree
    os_parts: OsPartitionSet
    registry: Registry | None
    registrable_fstypes: frozenset[str]


def gather(ctx: "Context", registry: Registry | None) -> Facts:
    """One lsblk call and the OS partition set (the root-only source as root)."""
    return Facts(
        tree=blockdev.read_tree(ctx),
        os_parts=ctx.platform.os_partitions(ctx, as_root=ctx.euid == 0),
        registry=registry,
        registrable_fstypes=ctx.platform.registrable_fstypes,
    )


def is_mapping(device: BlockDevice) -> bool:
    """A device-mapper device: the inside of a container, never a volume itself."""
    return device.type == CRYPT_TYPE or device.kname.startswith(DM_PREFIX)


def container(device: BlockDevice, tree: DeviceTree) -> BlockDevice | None:
    """The device a mapping sits on (its first parent in the tree), or None."""
    parents = tree.parents.get(device.kname, ())
    return tree.devices.get(parents[0]) if parents else None


def bitlocker_container(device: BlockDevice, tree: DeviceTree) -> BlockDevice | None:
    """The BitLocker container under a mapping, or None for any other mapping."""
    found = container(device, tree)
    return found if found is not None and found.fstype == BITLOCKER else None


def why_not_registrable(device: BlockDevice, facts: Facts) -> str | None:
    """The ``scan`` reason ``device`` cannot be registered; None: registrable."""
    if facts.registry is None:
        return REGISTRY_UNUSABLE
    return device_problem(device, facts) or _registered(device, facts.registry)


def why_not_mountable(device: BlockDevice, facts: Facts) -> str | None:
    """D013: why ``mount --device`` refuses an unregistered ``device``; None: it may.

    A mapping is judged by its BitLocker container, whose instance mounts it.
    """
    if not is_mapping(device):
        return device_problem(device, facts)
    found = bitlocker_container(device, facts.tree)
    if found is None:
        return _mapping_reason(device, facts.tree)
    return device_problem(found, facts)


def device_problem(device: BlockDevice, facts: Facts) -> str | None:
    """Steps 2 to 4: the device itself, whoever registered it."""
    if is_mapping(device):
        return _mapping_reason(device, facts.tree)
    if not facts.os_parts.known:
        return OS_SET_UNREADABLE
    if facts.os_parts.contains(device.kname, device.partuuid):
        return OS_PARTITION
    if device.fstype is None:
        return NO_FILESYSTEM
    if device.fstype == EXT4:
        return EXT4_HANDLED
    if device.fstype not in facts.registrable_fstypes:
        return UNSUPPORTED.format(fstype=device.fstype)
    return None


def _mapping_reason(device: BlockDevice, tree: DeviceTree) -> str:
    found = container(device, tree)
    if found is None:
        return MAPPING_WITHOUT_CONTAINER
    return MAPPING.format(container=f"/dev/{found.kname}")


def _registered(device: BlockDevice, registry: Registry) -> str | None:
    if device.uuid is None:
        return None
    volume = registry.by_uuid(device.uuid)
    if volume is not None:
        return REGISTERED.format(name=volume.name)
    if device.uuid.lower() in registry.blocked_uuids():
        return REGISTERED_INVALID
    return None
