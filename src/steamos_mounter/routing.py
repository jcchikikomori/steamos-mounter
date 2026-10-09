"""Device classification and routing: what an instance does for one device.

Design Doc "Device Classification and Routing", "Data Contracts >
routing.route", DD-02, DD-07, DD-16; ADR-0002 D3 and D4. ``route()`` is pure:
``reconcile.run`` gathers every fact in one pass (the lsblk tree, the registry,
the OS partition set, sysfs ``slaves``/``holders``/``dm/name`` and sysfs paths)
and executes the returned ``Route``. Bad facts never raise; they end in
``REJECT``, ``IGNORE`` or ``FAIL_CLOSED``.

Every decision keys on UUIDs, never on kernel names: the same drive can come
up as ``sda`` one day and ``sdb`` the next.

The order of the checks is the order of the rule tuples ``AUTO_RULES`` and
``REGISTERED_RULES``; the first rule that decides wins. Both start with the
subject checks (kname validation, then presence in the tree), and each ends
with a default rule that always decides.

Reasons are journal words, except the three ``REFUSE_REGISTERED`` reasons,
which are record reasons from ``state.KNOWN_REASONS``.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from steamos_mounter.bitlocker import is_tool_mapping
from steamos_mounter.blockdev import KNAME_RE, BlockDevice, DeviceTree
from steamos_mounter.errors import RegistryError
from steamos_mounter.escape import auto_instance, registered_instance, unit_name
from steamos_mounter.model import InstanceKind, Registry, Volume
from steamos_mounter.platforms.base import OsPartitionSet, Platform

REGISTERED_TEMPLATE: Final = "steamos-mounter@"
AUTO_TEMPLATE: Final = "steamos-mounter-auto@"
BITLOCKER: Final = "BitLocker"
EXT4: Final = "ext4"
CRYPT_TYPE: Final = "crypt"
LOOP_TYPE: Final = "loop"
DM_PREFIX: Final = "dm-"

# Record reasons (state.KNOWN_REASONS[MountFailed]).
REGISTRY_ENTRY_INVALID: Final = "registry_entry_invalid"
OS_PARTITION: Final = "os_partition"
FSTYPE_MISMATCH: Final = "fstype_mismatch"

# Journal reasons.
INVALID_KNAME: Final = "invalid kernel device name"
NOT_PRESENT: Final = "device not present"
NOT_BITLOCKER_MAPPING: Final = "not a BitLocker mapping"
OWN_MAPPING_REASON: Final = "own mapping: the opener mounts it"
DELEGATED: Final = "foreign unlock: the partition instance mounts it"
NO_CONTAINER_INSTANCE: Final = "no instance name for the container"
REGISTRY_UNREADABLE: Final = "registry unreadable"
REGISTERED_ELSEWHERE: Final = "registered: the registered instance owns it"
DUPLICATE_UUID: Final = "duplicate UUID: served by /dev/{other}"
OS_SET_UNKNOWN: Final = "cannot read the SteamOS partition list"
OS_PARTITION_WORDS: Final = "OS partition"
EXT4_WORDS: Final = "ext4: SteamOS handles it"
NO_FILESYSTEM: Final = "no filesystem"
UNSUPPORTED_TYPE: Final = "unsupported filesystem type"
LOOP_DEVICE: Final = "loop device: registration only"
INTERNAL_DISK: Final = "internal disk"
LOCKED: Final = "locked BitLocker container"
FOREIGN_UNLOCK: Final = "unlocked by someone else"
AUTO_VOLUME: Final = "unregistered removable volume"
MAPPING_REGISTERED: Final = "unlocked mapping: register its container"
STALE_LINK: Final = "stale link"
REGISTERED_VOLUME: Final = "registered volume"
REGISTERED_UNLOCKED: Final = "registered BitLocker volume, already unlocked"
REGISTERED_LOCKED: Final = "registered BitLocker volume, locked"


class Action(StrEnum):
    REJECT = "reject"
    IGNORE = "ignore"
    FAIL_CLOSED = "fail-closed"
    YIELD = "yield"
    DELEGATE = "delegate"
    OWN_MAPPING = "own-mapping"
    MOUNT_REGISTERED = "mount-registered"
    UNLOCK_REGISTERED = "unlock-registered"
    MOUNT_INNER_REGISTERED = "mount-inner-registered"
    REFUSE_REGISTERED = "refuse-registered"
    SKIP_LOCKED = "skip-locked"
    AUTO_MOUNT = "auto-mount"
    AUTO_MOUNT_INNER = "auto-mount-inner"


@dataclass(frozen=True, slots=True)
class Route:
    """The decision. ``device`` is the instance's own device when it is known;
    ``inner`` is the mapping on a BitLocker container (None when the tree does
    not list it yet); ``volume`` is the valid registry entry for the UUID."""

    action: Action
    reason: str
    device: BlockDevice | None = None
    volume: Volume | None = None
    inner: BlockDevice | None = None
    mapping_name: str | None = None
    delegate_unit: str | None = None


@dataclass(frozen=True, slots=True)
class RoutingInput:
    """Facts gathered in one pass. ``slaves`` and ``holders`` are sysfs
    listings of ``kname``; ``dm_names`` and ``syspaths`` are keyed by kname."""

    kind: InstanceKind
    kname: str
    tree: DeviceTree
    registry: Registry | RegistryError
    os_parts: OsPartitionSet
    slaves: tuple[str, ...]
    holders: tuple[str, ...]
    dm_names: Mapping[str, str]
    syspaths: Mapping[str, str]
    platform: Platform


@dataclass(frozen=True, slots=True)
class _Case:
    """``RoutingInput`` plus what the rules derive from it, worked out once.

    Built only after the subject rules, so ``device`` is always in the tree.
    ``registry`` is None when the registry is unusable.
    """

    inp: RoutingInput
    device: BlockDevice
    registry: Registry | None
    uuid: str | None  # lowercased
    blocked: frozenset[str]
    volume: Volume | None
    mapping: str | None  # the dm-* holder of the device


Rule = Callable[[_Case], Route | None]
Subject = Callable[[RoutingInput], Route | None]


def route(inp: RoutingInput) -> Route:
    """The ``Route`` for ``inp``; pure and deterministic, never raises."""
    subject_rules, rules, default = _TABLES[inp.kind]
    for subject_rule in subject_rules:
        decided = subject_rule(inp)
        if decided is not None:
            return decided
    case = _case(inp)
    for rule in rules:
        decided = rule(case)
        if decided is not None:
            return decided
    return default(case)


def _case(inp: RoutingInput) -> _Case:
    device = inp.tree.devices[inp.kname]  # present: _ignore_missing ran first
    registry = inp.registry if isinstance(inp.registry, Registry) else None
    uuid = device.uuid.lower() if device.uuid else None
    blocked: frozenset[str] = frozenset()
    volume = None
    if registry is not None:
        blocked = registry.blocked_uuids()
        volume = registry.by_uuid(uuid) if uuid else None
    return _Case(
        inp=inp,
        device=device,
        registry=registry,
        uuid=uuid,
        blocked=blocked,
        volume=volume,
        mapping=next((h for h in inp.holders if h.startswith(DM_PREFIX)), None),
    )


def _route(
    case: _Case,
    action: Action,
    reason: str,
    *,
    volume: Volume | None = None,
    inner: BlockDevice | None = None,
    mapping_name: str | None = None,
    delegate_unit: str | None = None,
) -> Route:
    """A ``Route`` for the case's own device."""
    return Route(
        action=action,
        reason=reason,
        device=case.device,
        volume=volume,
        inner=inner,
        mapping_name=mapping_name,
        delegate_unit=delegate_unit,
    )


# --- subject rules (both kinds) ---------------------------------------------------


def _reject_bad_kname(inp: RoutingInput) -> Route | None:
    if KNAME_RE.fullmatch(inp.kname) is None:
        return Route(action=Action.REJECT, reason=INVALID_KNAME)
    return None


def _ignore_missing(inp: RoutingInput) -> Route | None:
    if inp.kname not in inp.tree.devices:
        return Route(action=Action.IGNORE, reason=NOT_PRESENT)
    return None


# --- auto rules -------------------------------------------------------------------


def _is_mapping(device: BlockDevice) -> bool:
    return device.type == CRYPT_TYPE or device.kname.startswith(DM_PREFIX)


def _bitlocker_container(case: _Case) -> BlockDevice | None:
    slaves = case.inp.slaves
    if len(slaves) != 1:
        return None
    container = case.inp.tree.devices.get(slaves[0])
    if container is None or container.fstype != BITLOCKER:
        return None
    return container


def _route_mapping(case: _Case) -> Route | None:
    """``dm-*``: only ever ``IGNORE``, ``OWN_MAPPING`` or ``DELEGATE``."""
    if not _is_mapping(case.device):
        return None
    container = _bitlocker_container(case)
    if container is None:
        return _route(case, Action.IGNORE, NOT_BITLOCKER_MAPPING)
    name = case.inp.dm_names.get(case.device.kname)
    if is_tool_mapping(name):
        return _route(case, Action.OWN_MAPPING, OWN_MAPPING_REASON, mapping_name=name)
    if case.registry is None:
        # Which instance owns the container is unknown; neither would mount.
        return _route(case, Action.IGNORE, REGISTRY_UNREADABLE, mapping_name=name)
    volume = case.registry.by_uuid(container.uuid) if container.uuid else None
    unit = _container_unit(case, container, volume)
    if unit is None:
        return _route(case, Action.IGNORE, NO_CONTAINER_INSTANCE, mapping_name=name)
    return _route(
        case,
        Action.DELEGATE,
        DELEGATED,
        volume=volume,
        mapping_name=name,
        delegate_unit=unit,
    )


def _container_unit(
    case: _Case, container: BlockDevice, volume: Volume | None
) -> str | None:
    """The registered unit when registered, else the container's auto unit."""
    try:
        if volume is not None:
            return unit_name(REGISTERED_TEMPLATE, registered_instance(volume.uuid))
        syspath = case.inp.syspaths.get(container.kname)
        if syspath is None:
            return None
        return unit_name(AUTO_TEMPLATE, auto_instance(syspath))
    except ValueError:
        return None


def _fail_closed_on_registry(case: _Case) -> Route | None:
    if case.registry is None:
        return _route(case, Action.FAIL_CLOSED, REGISTRY_UNREADABLE)
    return None


def _yield_registered(case: _Case) -> Route | None:
    if case.uuid is None or case.uuid not in case.blocked:
        return None
    others = [
        other.kname
        for other in case.inp.tree.by_uuid(case.uuid)
        if other.kname != case.device.kname
    ]
    reason = DUPLICATE_UUID.format(other=others[0]) if others else REGISTERED_ELSEWHERE
    return _route(case, Action.YIELD, reason, volume=case.volume)


def _fail_closed_on_unknown_os_set(case: _Case) -> Route | None:
    if not case.inp.os_parts.known:
        return _route(case, Action.FAIL_CLOSED, OS_SET_UNKNOWN)
    return None


def _is_os_partition(case: _Case) -> bool:
    return case.inp.os_parts.contains(case.device.kname, case.device.partuuid)


def _ignore_os_partition(case: _Case) -> Route | None:
    if _is_os_partition(case):
        return _route(case, Action.IGNORE, OS_PARTITION_WORDS)
    return None


def _ignore_unsupported_type(case: _Case) -> Route | None:
    fstype = case.device.fstype
    if fstype is None:
        return _route(case, Action.IGNORE, NO_FILESYSTEM)
    if fstype == EXT4:
        return _route(case, Action.IGNORE, EXT4_WORDS)
    if fstype not in case.inp.platform.auto_fstypes | {BITLOCKER}:
        return _route(case, Action.IGNORE, UNSUPPORTED_TYPE)
    return None


def _ignore_not_removable(case: _Case) -> Route | None:
    top = case.inp.tree.top_disk(case.device.kname)
    if top is not None and top.type == LOOP_TYPE:
        return _route(case, Action.IGNORE, LOOP_DEVICE)  # DD-16
    if case.inp.tree.is_removable(case.device.kname) is not True:
        return _route(case, Action.IGNORE, INTERNAL_DISK)  # ADR-0002 D3, fail safe
    return None


def _inner(case: _Case) -> BlockDevice | None:
    """The mapping's device; None while the tree does not list it yet."""
    return case.inp.tree.devices.get(case.mapping) if case.mapping else None


def _inner_name(case: _Case) -> str | None:
    return case.inp.dm_names.get(case.mapping) if case.mapping else None


def _skip_locked(case: _Case) -> Route | None:
    if case.device.fstype == BITLOCKER and case.mapping is None:
        return _route(case, Action.SKIP_LOCKED, LOCKED)
    return None


def _auto_mount_inner(case: _Case) -> Route | None:
    if case.device.fstype == BITLOCKER:
        return _route(
            case,
            Action.AUTO_MOUNT_INNER,
            FOREIGN_UNLOCK,
            inner=_inner(case),
            mapping_name=_inner_name(case),
        )
    return None


def _auto_mount(case: _Case) -> Route:
    return _route(case, Action.AUTO_MOUNT, AUTO_VOLUME)


# --- registered rules -------------------------------------------------------------


def _ignore_registered_mapping(case: _Case) -> Route | None:
    # add refuses crypt devices: only a hand-edited inner UUID lands here.
    if _is_mapping(case.device):
        return _route(case, Action.IGNORE, MAPPING_REGISTERED)
    return None


def _ignore_stale_link(case: _Case) -> Route | None:
    if case.uuid is None or case.uuid not in case.blocked:
        return _route(case, Action.IGNORE, STALE_LINK)
    return None


def _refuse_invalid_entry(case: _Case) -> Route | None:
    if case.volume is None:
        return _route(case, Action.REFUSE_REGISTERED, REGISTRY_ENTRY_INVALID)
    return None


def _refuse_os_partition(case: _Case) -> Route | None:
    # An unknown set does not stop a registered volume (DD-02).
    if case.inp.os_parts.known and _is_os_partition(case):
        return _route(case, Action.REFUSE_REGISTERED, OS_PARTITION, volume=case.volume)
    return None


def _registered_fstype(case: _Case) -> str | None:
    return case.volume.fstype if case.volume else None


def _refuse_fstype_mismatch(case: _Case) -> Route | None:
    if case.device.fstype != _registered_fstype(case):  # DD-07
        return _route(
            case, Action.REFUSE_REGISTERED, FSTYPE_MISMATCH, volume=case.volume
        )
    return None


def _mount_registered(case: _Case) -> Route | None:
    if case.device.fstype != BITLOCKER:
        return _route(
            case, Action.MOUNT_REGISTERED, REGISTERED_VOLUME, volume=case.volume
        )
    return None


def _mount_inner_registered(case: _Case) -> Route | None:
    if case.mapping is not None:  # tool mapping or foreign (AC-059, AC-060)
        return _route(
            case,
            Action.MOUNT_INNER_REGISTERED,
            REGISTERED_UNLOCKED,
            volume=case.volume,
            inner=_inner(case),
            mapping_name=_inner_name(case),
        )
    return None


def _unlock_registered(case: _Case) -> Route:
    return _route(case, Action.UNLOCK_REGISTERED, REGISTERED_LOCKED, volume=case.volume)


# --- the order --------------------------------------------------------------------

SUBJECT_RULES: Final[tuple[Subject, ...]] = (_reject_bad_kname, _ignore_missing)
AUTO_RULES: Final[tuple[Rule, ...]] = (
    _route_mapping,
    _fail_closed_on_registry,
    _yield_registered,
    _fail_closed_on_unknown_os_set,
    _ignore_os_partition,
    _ignore_unsupported_type,
    _ignore_not_removable,
    _skip_locked,
    _auto_mount_inner,
)
REGISTERED_RULES: Final[tuple[Rule, ...]] = (
    _ignore_registered_mapping,
    _fail_closed_on_registry,
    _ignore_stale_link,
    _refuse_invalid_entry,
    _refuse_os_partition,
    _refuse_fstype_mismatch,
    _mount_registered,
    _mount_inner_registered,
)
Default = Callable[[_Case], Route]
_TABLES: Final[
    Mapping[InstanceKind, tuple[tuple[Subject, ...], tuple[Rule, ...], Default]]
] = {
    InstanceKind.AUTO: (SUBJECT_RULES, AUTO_RULES, _auto_mount),
    InstanceKind.REGISTERED: (SUBJECT_RULES, REGISTERED_RULES, _unlock_registered),
}
