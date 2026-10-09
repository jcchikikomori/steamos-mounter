"""Device classification and routing, rule by rule.

Design Doc "Device Classification and Routing" (the order of the checks is
the order of the rules), "Data Contracts > routing.route" (the three
invariants), DD-02 (unknown OS set fails closed), DD-07 (``fstype_mismatch``),
DD-16 (loop devices never auto-mount) and ADR-0002 D3/D4; PRD Won't list
(other encryption formats and filesystems are ignored).

Trees are built with ``lsblk_device`` and parsed by the real
``parse_lsblk_json``; registries are TOML text parsed by the real
``config.parse``. Every decision is keyed on UUIDs: a test below renames the
WD drive to ``sda`` (as it appeared on 2026-10-09) and expects the same routes.
"""

import itertools
import json
from collections.abc import Iterable, Mapping
from typing import Any

import pytest

from steamos_mounter.blockdev import DeviceTree, parse_lsblk_json
from steamos_mounter.config import parse
from steamos_mounter.errors import RegistryError
from steamos_mounter.model import InstanceKind, Registry, VolumeState
from steamos_mounter.naming import sanitize_label, unique_auto_path
from steamos_mounter.platforms.base import OsPartitionSet
from steamos_mounter.routing import Action, Route, RoutingInput, route
from steamos_mounter.state import KNOWN_REASONS
from tests.helpers.builders import (
    RegistryVolume,
    lsblk_device,
    lsblk_tree,
    raw_registry_text,
    raw_volume_table,
    registry_text,
)
from tests.helpers.fake_platform import FakePlatform

AUTO = InstanceKind.AUTO
REGISTERED = InstanceKind.REGISTERED
MOUNT_BASE = "/run/media/deck"

STICK_UUID = "1A2B-3C4D"
OTHER_STICK_UUID = "5E6F-7A8B"
CONTAINER_UUID = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
INNER_UUID = "3C5E7A9B1D2F4E60"
OS_PARTUUID = "584a6949-4802-4d5a-b558-ceacc6c4852d"
STICK_PARTUUID = "affac936-01"
UDISKS_NAME = "OBAMA_BACKUP"
TOOL_MAPPING = f"steamos-mounter-{CONTAINER_UUID}"
CONTAINER_SYSPATH = "/sys/devices/pci0000:00/0000:04:00.3/usb2/2-1/block/sdc/sdc1"
CONTAINER_AUTO_UNIT = (
    "steamos-mounter-auto@sys-devices-pci0000:00-0000:04:00.3-usb2-2\\x2d1-block-"
    "sdc-sdc1.service"
)
CONTAINER_REGISTERED_UNIT = (
    "steamos-mounter@dev-disk-by\\x2duuid-0f1e2d3c\\x2d4b5a\\x2d4968\\x2d8776"
    "\\x2da5b4c3d2e1f0.service"
)

GAMES = RegistryVolume(
    name="GAMES", uuid=STICK_UUID, path=f"{MOUNT_BASE}/GAMES", fstype="exfat"
)
VAULT = RegistryVolume(
    name="VAULT", uuid=CONTAINER_UUID, path=f"{MOUNT_BASE}/VAULT", fstype="BitLocker"
)

KNOWN_OS_SET = OsPartitionSet(
    known=True,
    knames=frozenset(),
    partuuids=frozenset({OS_PARTUUID}),
    sources=("/run/udev/rules.d/90-holo-partsets-all.rules",),
)
UNKNOWN_OS_SET = OsPartitionSet(
    known=False, knames=frozenset(), partuuids=frozenset(), sources=()
)
UNUSABLE = RegistryError("the registry cannot be used", detail="not valid TOML")

MOUNT_ACTIONS = frozenset(
    {
        Action.MOUNT_REGISTERED,
        Action.MOUNT_INNER_REGISTERED,
        Action.UNLOCK_REGISTERED,
        Action.AUTO_MOUNT,
        Action.AUTO_MOUNT_INNER,
    }
)
AUTO_ACTIONS = frozenset({Action.AUTO_MOUNT, Action.AUTO_MOUNT_INNER})


# --- builders ---------------------------------------------------------------------


def tree_of(devices: Iterable[dict[str, Any]]) -> DeviceTree:
    return parse_lsblk_json(json.dumps(lsblk_tree(devices)).encode("utf-8"))


def partition(kname: str, disk: str, **columns: Any) -> dict[str, Any]:
    """A partition of ``disk``; ``hotplug`` follows the disk like lsblk's."""
    return lsblk_device(kname, {"pkname": disk, **columns})


def disk(
    kname: str, children: Iterable[dict[str, Any]] = (), **columns: Any
) -> dict[str, Any]:
    nodes = list(children)
    extra: dict[str, Any] = {"children": nodes} if nodes else {}
    return lsblk_device(kname, {"type": "disk", **columns, **extra})


def stick(
    fstype: str | None = "exfat",
    *,
    kname: str = "sdc1",
    disk_kname: str = "sdc",
    uuid: str | None = STICK_UUID,
    label: str | None = "GAMES",
    hotplug: bool = True,
    partuuid: str | None = STICK_PARTUUID,
    children: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """A disk holding one partition with ``fstype``."""
    nodes = list(children)
    extra: dict[str, Any] = {"children": nodes} if nodes else {}
    part = partition(
        kname,
        disk_kname,
        fstype=fstype,
        uuid=uuid,
        label=label,
        partuuid=partuuid,
        hotplug=hotplug,
        **extra,
    )
    return disk(disk_kname, [part], hotplug=hotplug)


def mapping(
    kname: str = "dm-1", *, container: str = "sdc1", fstype: str | None = "ntfs"
) -> dict[str, Any]:
    return lsblk_device(
        kname,
        {
            "type": "crypt",
            "fstype": fstype,
            "uuid": INNER_UUID,
            "label": "OBAMA",
            "pkname": container,
            "path": f"/dev/mapper/{UDISKS_NAME}",
        },
    )


def bitlocker_stick(*, unlocked: bool, hotplug: bool = True) -> dict[str, Any]:
    return stick(
        "BitLocker",
        uuid=CONTAINER_UUID,
        label="OBAMA BACKUP 1/2/2025",
        hotplug=hotplug,
        children=[mapping()] if unlocked else [],
    )


def registry_of(*volumes: RegistryVolume) -> Registry:
    return parse(registry_text(volumes), mount_base=MOUNT_BASE)


EMPTY_REGISTRY = registry_of()


def make_input(
    kname: str,
    tree: DeviceTree,
    *,
    kind: InstanceKind = AUTO,
    registry: Registry | RegistryError = EMPTY_REGISTRY,
    os_parts: OsPartitionSet = KNOWN_OS_SET,
    slaves: tuple[str, ...] = (),
    holders: tuple[str, ...] = (),
    dm_names: Mapping[str, str] | None = None,
    syspaths: Mapping[str, str] | None = None,
) -> RoutingInput:
    return RoutingInput(
        kind=kind,
        kname=kname,
        tree=tree,
        registry=registry,
        os_parts=os_parts,
        slaves=slaves,
        holders=holders,
        dm_names=dm_names if dm_names is not None else {},
        syspaths=syspaths if syspaths is not None else {},
        platform=FakePlatform(),
    )


def unlocked_inputs(
    kname: str, *, registry: Registry | RegistryError, **changes: Any
) -> RoutingInput:
    """``kname`` of a BitLocker stick ``sdc1`` that udisks unlocked as ``dm-1``."""
    facts: dict[str, Any] = {
        "slaves": ("sdc1",) if kname == "dm-1" else (),
        "holders": ("dm-1",) if kname == "sdc1" else (),
        "dm_names": {"dm-1": UDISKS_NAME},
        "syspaths": {"sdc1": CONTAINER_SYSPATH},
    }
    facts.update(changes)
    tree = tree_of([bitlocker_stick(unlocked=True)])
    return make_input(kname, tree, registry=registry, **facts)


# --- REJECT and missing devices ---------------------------------------------------


@pytest.mark.parametrize("kind", [AUTO, REGISTERED])
@pytest.mark.parametrize("kname", ["", "SDB1", "sdb1/..", "sd b1", "sdb1\n", "dm_0"])
def test_invalid_kernel_name_is_rejected(kind, kname):
    found = route(make_input(kname, tree_of([stick()]), kind=kind))

    assert found.action is Action.REJECT
    assert found.reason == "invalid kernel device name"
    assert found.device is None


@pytest.mark.parametrize("kind", [AUTO, REGISTERED])
def test_device_missing_from_the_tree_is_ignored(kind):
    found = route(make_input("sdz1", tree_of([stick()]), kind=kind))

    assert found == Route(action=Action.IGNORE, reason="device not present")


# --- auto path: exclusions --------------------------------------------------------

AUTO_EXCLUSIONS = {
    "ext4": (
        tree_of([stick("ext4")]),
        EMPTY_REGISTRY,
        Action.IGNORE,
        "ext4: SteamOS handles it",
    ),
    "os": (
        tree_of([stick("vfat", partuuid=OS_PARTUUID)]),
        EMPTY_REGISTRY,
        Action.IGNORE,
        "OS partition",
    ),
    "internal": (
        tree_of([stick("exfat", hotplug=False)]),
        EMPTY_REGISTRY,
        Action.IGNORE,
        "internal disk",
    ),
    "registered": (
        tree_of([stick("exfat")]),
        registry_of(GAMES),
        Action.YIELD,
        "registered: the registered instance owns it",
    ),
    "unsupported-crypto_LUKS": (
        tree_of([stick("crypto_LUKS")]),
        EMPTY_REGISTRY,
        Action.IGNORE,
        "unsupported filesystem type",
    ),
    "unsupported-xfs": (
        tree_of([stick("xfs")]),
        EMPTY_REGISTRY,
        Action.IGNORE,
        "unsupported filesystem type",
    ),
    "unsupported-swap": (
        tree_of([stick("swap")]),
        EMPTY_REGISTRY,
        Action.IGNORE,
        "unsupported filesystem type",
    ),
    "unsupported-null": (
        tree_of([stick(None, uuid=None, label=None)]),
        EMPTY_REGISTRY,
        Action.IGNORE,
        "no filesystem",
    ),
}


@pytest.mark.parametrize(
    ("tree", "registry", "action", "reason"),
    list(AUTO_EXCLUSIONS.values()),
    ids=list(AUTO_EXCLUSIONS),
)
def test_auto_exclusions(tree, registry, action, reason):
    found = route(make_input("sdc1", tree, registry=registry))

    assert found.action is action
    assert found.reason == reason
    assert found.device is not None
    assert found.device.kname == "sdc1"


def test_unknown_removable_class_is_internal():
    # sdc1 names a disk the tree does not hold: the chain cannot be followed.
    tree = tree_of([partition("sdc1", "sdc", fstype="exfat", uuid=STICK_UUID)])

    found = route(make_input("sdc1", tree))

    assert (found.action, found.reason) == (Action.IGNORE, "internal disk")


def test_os_partition_matched_by_kname_link():
    os_set = OsPartitionSet(
        known=True,
        knames=frozenset({"sdc1"}),
        partuuids=frozenset(),
        sources=("/dev/disk/by-partsets/all",),
    )

    found = route(make_input("sdc1", tree_of([stick()]), os_parts=os_set))

    assert (found.action, found.reason) == (Action.IGNORE, "OS partition")


def test_registered_uuid_matches_in_any_case():
    lower = RegistryVolume(
        name="GAMES", uuid=STICK_UUID.lower(), path=f"{MOUNT_BASE}/G", fstype="exfat"
    )

    found = route(make_input("sdc1", tree_of([stick()]), registry=registry_of(lower)))

    assert found.action is Action.YIELD


def test_invalid_registry_entry_still_blocks_auto_mount():
    text = raw_registry_text(
        [
            raw_volume_table(
                {
                    "name": "GAMES",
                    "uuid": STICK_UUID,
                    "path": "/etc/x",
                    "fstype": "exfat",
                }
            )
        ]
    )
    registry = parse(text, mount_base=MOUNT_BASE)

    found = route(make_input("sdc1", tree_of([stick()]), registry=registry))

    assert found.action is Action.YIELD
    assert found.volume is None


def test_unusable_registry_fails_closed_on_the_auto_path():
    found = route(make_input("sdc1", tree_of([stick()]), registry=UNUSABLE))

    assert found == Route(
        action=Action.FAIL_CLOSED,
        reason="registry unreadable",
        device=found.device,
    )
    assert found.device is not None


def test_absent_registry_file_routes_normally():
    absent = Registry(schema_version=1, volumes=(), invalid=())

    found = route(make_input("sdc1", tree_of([stick()]), registry=absent))

    assert found.action is Action.AUTO_MOUNT


# --- auto path: OS partition set unknown (EARS, DD-02) ----------------------------


def test_unknown_os_set_fails_closed_on_the_auto_path():
    found = route(make_input("sdc1", tree_of([stick()]), os_parts=UNKNOWN_OS_SET))

    assert found.action is Action.FAIL_CLOSED
    assert found.reason == "cannot read the SteamOS partition list"


def test_unknown_os_set_still_lets_a_registered_auto_instance_yield():
    found = route(
        make_input(
            "sdc1",
            tree_of([stick()]),
            registry=registry_of(GAMES),
            os_parts=UNKNOWN_OS_SET,
        )
    )

    assert found.action is Action.YIELD


def test_unknown_os_set_fails_closed_before_ext4():
    found = route(make_input("sdc1", tree_of([stick("ext4")]), os_parts=UNKNOWN_OS_SET))

    assert found.action is Action.FAIL_CLOSED


def test_os_partition_wins_over_ext4():
    tree = tree_of([stick("ext4", partuuid=OS_PARTUUID.upper())])

    found = route(make_input("sdc1", tree))

    assert found.reason == "OS partition"


# --- auto path: mounts ------------------------------------------------------------


def test_unregistered_removable_volume_auto_mounts():
    found = route(make_input("sdc1", tree_of([stick()])))

    assert found.action is Action.AUTO_MOUNT
    assert found.reason == "unregistered removable volume"
    assert found.device is not None
    assert (found.device.kname, found.device.uuid) == ("sdc1", STICK_UUID)
    assert (found.volume, found.inner, found.mapping_name) == (None, None, None)


@pytest.mark.parametrize("fstype", ["ntfs", "exfat", "vfat", "btrfs"])
def test_every_auto_type_auto_mounts(fstype):
    found = route(make_input("sdc1", tree_of([stick(fstype)])))

    assert found.action is Action.AUTO_MOUNT


def test_whole_disk_filesystem_auto():
    tree = tree_of(
        [disk("sdd", fstype="vfat", uuid=OTHER_STICK_UUID, label="CAM", hotplug=True)]
    )

    found = route(make_input("sdd", tree))

    assert found.action is Action.AUTO_MOUNT
    assert found.device is not None
    assert found.device.kname == "sdd"


def test_locked_container_skipped():
    found = route(make_input("sdc1", tree_of([bitlocker_stick(unlocked=False)])))

    assert found.action is Action.SKIP_LOCKED
    assert found.reason == "locked BitLocker container"
    assert (found.inner, found.mapping_name) == (None, None)


def test_non_mapping_holder_leaves_the_container_locked():
    # An md holder is not an unlocked mapping; the held check is the executor's.
    found = route(
        make_input(
            "sdc1", tree_of([bitlocker_stick(unlocked=False)]), holders=("md127",)
        )
    )

    assert found.action is Action.SKIP_LOCKED


def test_foreign_unlock_of_unregistered_container_auto_mounts_inner():
    found = route(unlocked_inputs("sdc1", registry=EMPTY_REGISTRY))

    assert found.action is Action.AUTO_MOUNT_INNER
    assert found.reason == "unlocked by someone else"
    assert found.device is not None
    assert found.inner is not None
    assert (found.device.kname, found.inner.kname) == ("sdc1", "dm-1")
    assert found.mapping_name == UDISKS_NAME


def test_mapping_absent_from_the_tree_still_counts_as_unlocked():
    # sysfs saw the mapping after lsblk ran: the inner device is not known yet.
    found = route(
        make_input(
            "sdc1",
            tree_of([bitlocker_stick(unlocked=False)]),
            holders=("dm-1",),
            dm_names={"dm-1": UDISKS_NAME},
        )
    )

    assert found.action is Action.AUTO_MOUNT_INNER
    assert found.inner is None
    assert found.mapping_name == UDISKS_NAME


def test_bitlocker_container_on_an_internal_disk_is_ignored():
    found = route(
        make_input("sdc1", tree_of([bitlocker_stick(unlocked=False, hotplug=False)]))
    )

    assert (found.action, found.reason) == (Action.IGNORE, "internal disk")


def test_registered_container_never_auto():
    registry = registry_of(VAULT)

    container = route(unlocked_inputs("sdc1", registry=registry))
    inner = route(unlocked_inputs("dm-1", registry=registry))

    assert container.action is Action.YIELD
    assert inner.action is Action.DELEGATE
    assert inner.delegate_unit == CONTAINER_REGISTERED_UNIT
    assert inner.volume is not None
    assert inner.volume.name == "VAULT"


# --- loop devices (DD-16) ---------------------------------------------------------


def loop_tree(*, hotplug: bool) -> DeviceTree:
    return tree_of(
        [
            lsblk_device(
                "loop0",
                {
                    "type": "loop",
                    "fstype": "ntfs",
                    "uuid": "01D95F1575592A31",
                    "label": "SCRATCH",
                    "hotplug": hotplug,
                },
            )
        ]
    )


@pytest.mark.parametrize("hotplug", [False, True])
def test_loop_devices_never_auto(hotplug):
    found = route(make_input("loop0", loop_tree(hotplug=hotplug)))

    assert (found.action, found.reason) == (
        Action.IGNORE,
        "loop device: registration only",
    )


def test_loop_device_can_be_registered():
    scratch = RegistryVolume(
        name="SCRATCH",
        uuid="01D95F1575592A31",
        path=f"{MOUNT_BASE}/SCRATCH",
        fstype="ntfs",
    )

    found = route(
        make_input(
            "loop0",
            loop_tree(hotplug=False),
            kind=REGISTERED,
            registry=registry_of(scratch),
        )
    )

    assert found.action is Action.MOUNT_REGISTERED


# --- auto path: mappings (dm-*) ---------------------------------------------------


def test_foreign_mapping_of_unregistered_container_delegates_to_its_auto_instance():
    found = route(unlocked_inputs("dm-1", registry=EMPTY_REGISTRY))

    assert found.action is Action.DELEGATE
    assert found.reason == "foreign unlock: the partition instance mounts it"
    assert found.delegate_unit == CONTAINER_AUTO_UNIT
    assert found.mapping_name == UDISKS_NAME
    assert found.volume is None
    assert found.device is not None
    assert found.device.kname == "dm-1"


def test_mapping_without_a_dm_name_is_foreign():
    found = route(unlocked_inputs("dm-1", registry=EMPTY_REGISTRY, dm_names={}))

    assert found.action is Action.DELEGATE
    assert found.mapping_name is None


def test_own_mapping_is_left_to_its_opener():
    found = route(
        unlocked_inputs(
            "dm-1", registry=registry_of(VAULT), dm_names={"dm-1": TOOL_MAPPING}
        )
    )

    assert found.action is Action.OWN_MAPPING
    assert found.reason == "own mapping: the opener mounts it"
    assert found.mapping_name == TOOL_MAPPING
    assert found.delegate_unit is None


@pytest.mark.parametrize(
    "slaves",
    [(), ("sdc1", "sdd1"), ("sdz1",), ("sdc",)],
    ids=["no-slave", "two-slaves", "slave-not-in-tree", "slave-not-bitlocker"],
)
def test_mapping_not_over_one_bitlocker_container_is_ignored(slaves):
    found = route(unlocked_inputs("dm-1", registry=EMPTY_REGISTRY, slaves=slaves))

    assert (found.action, found.reason) == (Action.IGNORE, "not a BitLocker mapping")


def test_dm_named_device_is_a_mapping_whatever_its_type():
    tree = tree_of([lsblk_device("dm-2", {"type": "lvm", "fstype": "exfat"})])

    found = route(make_input("dm-2", tree))

    assert (found.action, found.reason) == (Action.IGNORE, "not a BitLocker mapping")


def test_mapping_with_an_unusable_registry_is_ignored():
    found = route(unlocked_inputs("dm-1", registry=UNUSABLE))

    assert (found.action, found.reason) == (Action.IGNORE, "registry unreadable")


@pytest.mark.parametrize(
    "syspaths",
    [{}, {"sdc1": "sys/devices/relative"}, {"sdc1": "/sys/" + "d" * 300}],
    ids=["missing", "relative", "too-long"],
)
def test_mapping_whose_container_instance_cannot_be_named_is_ignored(syspaths):
    found = route(unlocked_inputs("dm-1", registry=EMPTY_REGISTRY, syspaths=syspaths))

    assert (found.action, found.reason) == (
        Action.IGNORE,
        "no instance name for the container",
    )


def test_delegation_to_a_registered_container_ignores_its_syspath():
    found = route(unlocked_inputs("dm-1", registry=registry_of(VAULT), syspaths={}))

    assert found.delegate_unit == CONTAINER_REGISTERED_UNIT


# --- registered path --------------------------------------------------------------


def registered_input(
    kname: str, tree: DeviceTree, registry: Registry | RegistryError, **changes: Any
) -> RoutingInput:
    return make_input(kname, tree, kind=REGISTERED, registry=registry, **changes)


def test_registered_volume_mounts_at_its_path():
    found = route(registered_input("sdc1", tree_of([stick()]), registry_of(GAMES)))

    assert found.action is Action.MOUNT_REGISTERED
    assert found.reason == "registered volume"
    assert found.volume is not None
    assert found.volume.path == f"{MOUNT_BASE}/GAMES"


def test_registered_volume_mounts_while_the_os_set_is_unknown():
    found = route(
        registered_input(
            "sdc1", tree_of([stick()]), registry_of(GAMES), os_parts=UNKNOWN_OS_SET
        )
    )

    assert found.action is Action.MOUNT_REGISTERED


def test_registered_volume_on_an_internal_disk_mounts():
    tree = tree_of([stick(hotplug=False)])

    found = route(registered_input("sdc1", tree, registry_of(GAMES)))

    assert found.action is Action.MOUNT_REGISTERED


def test_unusable_registry_fails_closed_on_the_registered_path():
    found = route(registered_input("sdc1", tree_of([stick()]), UNUSABLE))

    assert (found.action, found.reason) == (Action.FAIL_CLOSED, "registry unreadable")
    assert found.volume is None


@pytest.mark.parametrize(
    "tree",
    [tree_of([stick(uuid=OTHER_STICK_UUID)]), tree_of([stick(uuid=None)])],
    ids=["other-uuid", "no-uuid"],
)
def test_link_to_an_unregistered_uuid_is_stale(tree):
    found = route(registered_input("sdc1", tree, registry_of(GAMES)))

    assert (found.action, found.reason) == (Action.IGNORE, "stale link")


def test_stale_link_with_an_absent_registry_file():
    found = route(registered_input("sdc1", tree_of([stick()]), EMPTY_REGISTRY))

    assert (found.action, found.reason) == (Action.IGNORE, "stale link")


def test_invalid_registry_entry_is_refused():
    text = raw_registry_text(
        [
            raw_volume_table(
                {
                    "name": "GAMES",
                    "uuid": STICK_UUID,
                    "path": "/etc/x",
                    "fstype": "exfat",
                }
            )
        ]
    )

    found = route(
        registered_input("sdc1", tree_of([stick()]), parse(text, mount_base=MOUNT_BASE))
    )

    assert found.action is Action.REFUSE_REGISTERED
    assert found.reason == "registry_entry_invalid"
    assert found.volume is None


def test_registered_os_partition_is_refused():
    tree = tree_of([stick(partuuid=OS_PARTUUID)])

    found = route(registered_input("sdc1", tree, registry_of(GAMES)))

    assert (found.action, found.reason) == (Action.REFUSE_REGISTERED, "os_partition")
    assert found.volume is not None


@pytest.mark.parametrize("live", ["ntfs", "BITLOCKER", None])
def test_live_type_other_than_the_registered_one_is_refused(live):
    found = route(registered_input("sdc1", tree_of([stick(live)]), registry_of(GAMES)))

    assert (found.action, found.reason) == (
        Action.REFUSE_REGISTERED,
        "fstype_mismatch",
    )


def test_registered_refusal_reasons_are_known_record_reasons():
    reasons = {"registry_entry_invalid", "os_partition", "fstype_mismatch"}

    assert reasons <= KNOWN_REASONS[VolumeState.MOUNT_FAILED]


def test_locked_registered_container_unlocks():
    tree = tree_of([bitlocker_stick(unlocked=False)])

    found = route(registered_input("sdc1", tree, registry_of(VAULT)))

    assert found.action is Action.UNLOCK_REGISTERED
    assert found.reason == "registered BitLocker volume, locked"
    assert found.volume is not None
    assert found.volume.name == "VAULT"


@pytest.mark.parametrize("name", [UDISKS_NAME, TOOL_MAPPING])
def test_unlocked_registered_container_mounts_inner(name):
    found = route(
        unlocked_inputs(
            "sdc1",
            registry=registry_of(VAULT),
            kind=REGISTERED,
            dm_names={"dm-1": name},
        )
    )

    assert found.action is Action.MOUNT_INNER_REGISTERED
    assert found.reason == "registered BitLocker volume, already unlocked"
    assert found.inner is not None
    assert found.inner.kname == "dm-1"
    assert found.mapping_name == name


def test_registered_link_to_a_mapping_is_ignored():
    # add refuses crypt devices; only a hand edit can register an inner UUID.
    inner = RegistryVolume(
        name="INNER", uuid=INNER_UUID, path=f"{MOUNT_BASE}/INNER", fstype="ntfs"
    )

    found = route(unlocked_inputs("dm-1", registry=registry_of(inner), kind=REGISTERED))

    assert (found.action, found.reason) == (
        Action.IGNORE,
        "unlocked mapping: register its container",
    )


# --- duplicate UUIDs and kernel names ---------------------------------------------


def two_sticks_one_uuid() -> DeviceTree:
    return tree_of(
        [
            stick(kname="sdc1", disk_kname="sdc"),
            stick(kname="sdd1", disk_kname="sdd"),
        ]
    )


def test_duplicate_uuid_registered_instance_serves_the_by_uuid_target():
    # /dev/disk/by-uuid/<UUID> resolves to sdd1, so the instance routes sdd1.
    found = route(registered_input("sdd1", two_sticks_one_uuid(), registry_of(GAMES)))

    assert found.action is Action.MOUNT_REGISTERED
    assert found.device is not None
    assert found.device.kname == "sdd1"


def test_duplicate_uuid_other_auto_instance_yields():
    found = route(
        make_input("sdc1", two_sticks_one_uuid(), registry=registry_of(GAMES))
    )

    assert found.action is Action.YIELD
    assert found.reason == "duplicate UUID: served by /dev/sdd1"


def test_two_unregistered_sticks_with_one_uuid_get_two_distinct_paths():
    tree = two_sticks_one_uuid()
    taken: set[str] = set()
    paths = []
    for kname in ("sdc1", "sdd1"):
        found = route(make_input(kname, tree))
        assert found.action is Action.AUTO_MOUNT
        assert found.device is not None
        name = sanitize_label(found.device.label)
        path = unique_auto_path(MOUNT_BASE, name, taken.__contains__)
        taken.add(path)
        paths.append(path)

    assert paths == [f"{MOUNT_BASE}/GAMES", f"{MOUNT_BASE}/GAMES-2"]


def test_routes_follow_the_uuid_when_the_drive_changes_kernel_name():
    # 2026-10-09: the WD drive came up as sda; an unregistered stick took sdb.
    mediabox = RegistryVolume(
        name="MEDIABOX",
        uuid="01D95F1575592A30",
        path=f"{MOUNT_BASE}/MEDIABOX",
        fstype="ntfs",
    )
    tree = tree_of(
        [
            stick("ntfs", kname="sda5", disk_kname="sda", uuid=mediabox.uuid),
            stick("exfat", kname="sdb5", disk_kname="sdb", uuid=STICK_UUID),
        ]
    )
    registry = registry_of(mediabox)

    assert route(registered_input("sda5", tree, registry)).action is (
        Action.MOUNT_REGISTERED
    )
    assert route(make_input("sda5", tree, registry=registry)).action is Action.YIELD
    assert route(make_input("sdb5", tree, registry=registry)).action is (
        Action.AUTO_MOUNT
    )
    assert route(registered_input("sdb5", tree, registry)).reason == "stale link"


# --- routing.route data contract: invariants --------------------------------------

REGISTRIES: dict[str, Registry | RegistryError] = {
    "empty": EMPTY_REGISTRY,
    "stick": registry_of(GAMES),
    "container": registry_of(VAULT),
    "both": registry_of(GAMES, VAULT),
    "unusable": UNUSABLE,
}
OS_SETS = {"known": KNOWN_OS_SET, "unknown": UNKNOWN_OS_SET}
TREES = {
    "stick": tree_of([stick()]),
    "internal-stick": tree_of([stick(hotplug=False)]),
    "os-stick": tree_of([stick(partuuid=OS_PARTUUID)]),
    "ntfs-stick": tree_of([stick("ntfs")]),
    "locked": tree_of([bitlocker_stick(unlocked=False)]),
    "unlocked": tree_of([bitlocker_stick(unlocked=True)]),
    "two-sticks": two_sticks_one_uuid(),
}
KNAMES = ("sdc", "sdc1", "sdd1", "dm-1", "Bad!")
DM_NAMES = ({"dm-1": UDISKS_NAME}, {"dm-1": TOOL_MAPPING}, {})


def every_case() -> Iterable[tuple[str, RoutingInput]]:
    """Every combination of the dimensions above, with sysfs facts to match."""
    dimensions = itertools.product(
        REGISTRIES.items(),
        OS_SETS.items(),
        TREES.items(),
        KNAMES,
        (AUTO, REGISTERED),
        DM_NAMES,
    )
    for (r_id, registry), (o_id, os_set), (
        t_id,
        tree,
    ), kname, kind, names in dimensions:
        inp = make_input(
            kname,
            tree,
            kind=kind,
            registry=registry,
            os_parts=os_set,
            slaves=("sdc1",) if kname == "dm-1" else (),
            holders=("dm-1",) if kname == "sdc1" and "dm-1" in tree.devices else (),
            dm_names=names,
            syspaths={"sdc1": CONTAINER_SYSPATH},
        )
        yield f"{r_id}/{o_id}/{t_id}/{kname}/{kind}/{sorted(names.values())}", inp


CASES = list(every_case())


def test_invariant_cases_cover_every_action():
    actions = {route(inp).action for _case_id, inp in CASES}

    assert actions == set(Action)


def test_every_route_has_a_reason_and_never_raises():
    empty = [case_id for case_id, inp in CASES if not route(inp).reason]

    assert empty == []


def test_route_is_deterministic():
    assert all(route(inp) == route(inp) for _case_id, inp in CASES)


def test_registered_uuid_is_never_auto_mounted():
    offenders = []
    for case_id, inp in CASES:
        found = route(inp)
        device = inp.tree.devices.get(inp.kname)
        registry = inp.registry
        blocked = isinstance(registry, Registry) and (
            device is not None
            and device.uuid is not None
            and device.uuid.lower() in registry.blocked_uuids()
        )
        if blocked and found.action in AUTO_ACTIONS:
            offenders.append(case_id)

    assert offenders == []


def test_unknown_os_set_never_auto_mounts():
    offenders = [
        case_id
        for case_id, inp in CASES
        if not inp.os_parts.known and route(inp).action in AUTO_ACTIONS
    ]

    assert offenders == []


def test_dm_device_never_gets_a_mount_action():
    allowed = {Action.DELEGATE, Action.OWN_MAPPING, Action.IGNORE}
    found = {
        route(inp).action for _case_id, inp in CASES if inp.kname.startswith("dm-")
    }

    assert found <= allowed
    assert not found & MOUNT_ACTIONS
