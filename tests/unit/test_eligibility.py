"""commands.eligibility: the "registrable or why not" reasons, in their order.

Design Doc "CLI Contract > Commands" (``scan`` reasons, ``add`` step 3,
``mount`` D013), DD-02, DD-16 and D007. Pure decisions over an lsblk tree,
an OS partition set and a registry built in the test.
"""

import json

import pytest

from steamos_mounter.blockdev import parse_lsblk_json
from steamos_mounter.commands import eligibility
from steamos_mounter.commands.eligibility import Facts
from steamos_mounter.model import InvalidEntry, Registry, Volume
from steamos_mounter.platforms.base import OsPartitionSet
from steamos_mounter.platforms.steamos import REGISTRABLE_FSTYPES
from tests.helpers.builders import lsblk_device, lsblk_tree

KNOWN = OsPartitionSet(
    known=True,
    knames=frozenset({"nvme0n1p4"}),
    partuuids=frozenset({"afc32485-4f6b-4972-a880-a6fb77f8940d"}),
    sources=("holo",),
)
UNKNOWN = OsPartitionSet(
    known=False, knames=frozenset(), partuuids=frozenset(), sources=()
)
EMPTY = Registry(schema_version=1, volumes=(), invalid=())
STICK = Volume(
    name="GAMES",
    uuid="C40C-B21F",
    path="/run/media/deck/GAMES",
    fstype="exfat",
    drivers=None,
    nosuid=True,
    nodev=True,
)


def facts(*devices, os_parts=KNOWN, registry=EMPTY) -> Facts:
    tree = parse_lsblk_json(json.dumps(lsblk_tree(devices)).encode())
    return Facts(
        tree=tree,
        os_parts=os_parts,
        registry=registry,
        registrable_fstypes=REGISTRABLE_FSTYPES,
    )


def device(kname: str, **columns):
    return lsblk_device(kname, columns)


BITLOCKER_TREE = device(
    "sdb1",
    fstype="BitLocker",
    uuid="658207d5-5177-4a52-a297-31643c64724d",
    children=[device("dm-0", type="crypt", fstype="ntfs", pkname="sdb1")],
)


@pytest.mark.parametrize(
    ("node", "kname", "reason"),
    [
        (device("sdc1", fstype="exfat", uuid="C40C-B21F"), "sdc1", None),
        (device("nvme0n1p4", fstype="btrfs"), "nvme0n1p4", "OS partition"),
        (
            device(
                "nvme0n1p8",
                fstype="ext4",
                partuuid="AFC32485-4F6B-4972-A880-A6FB77F8940D",
            ),
            "nvme0n1p8",
            "OS partition",
        ),
        (device("sdc1"), "sdc1", "no filesystem"),
        (device("sdc1", fstype="ext4"), "sdc1", "ext4 (SteamOS handles it)"),
        (device("sdc1", fstype="xfs"), "sdc1", "unsupported type xfs"),
        (device("loop0", type="loop", fstype="btrfs"), "loop0", None),
        (device("sdc", type="disk", fstype="vfat"), "sdc", None),
        (BITLOCKER_TREE, "dm-0", "unlocked mapping: register its container /dev/sdb1"),
        (
            device("dm-3", type="crypt", fstype="ntfs"),
            "dm-3",
            "unlocked mapping without a container",
        ),
    ],
    ids=[
        "registrable",
        "os-kname",
        "os-partuuid-any-case",
        "no-fs",
        "ext4",
        "xfs",
        "loop",
        "whole-disk",
        "mapping",
        "mapping-alone",
    ],
)
def test_why_not_registrable(node, kname, reason):
    found = facts(node)

    assert eligibility.why_not_registrable(found.tree.devices[kname], found) == reason


def test_an_unusable_registry_comes_first():
    found = facts(device("sdc1", fstype="exfat"), registry=None)

    assert eligibility.why_not_registrable(found.tree.devices["sdc1"], found) == (
        "registry unusable"
    )


def test_an_unknown_os_set_fails_closed_before_the_filesystem():
    found = facts(device("sdc1", fstype="ext4"), os_parts=UNKNOWN)

    assert eligibility.why_not_registrable(found.tree.devices["sdc1"], found) == (
        "OS partition list unreadable"
    )


def test_registered_uuids_by_valid_and_invalid_entries():
    registered = Registry(1, (STICK,), (InvalidEntry(0, "01D95F1575592A30", "bad"),))
    found = facts(
        device("sdc1", fstype="exfat", uuid="c40c-b21f"),
        device("sdd1", fstype="ntfs", uuid="01d95f1575592a30"),
        device("sde1", fstype="ntfs", uuid="1111222233334444"),
        registry=registered,
    )
    devices = found.tree.devices

    assert eligibility.why_not_registrable(devices["sdc1"], found) == (
        "already registered as GAMES"
    )
    assert eligibility.why_not_registrable(devices["sdd1"], found) == (
        "already registered by an invalid registry entry"
    )
    assert eligibility.why_not_registrable(devices["sde1"], found) is None


def test_a_mapping_is_mountable_through_its_bitlocker_container():
    found = facts(BITLOCKER_TREE)
    mapping = found.tree.devices["dm-0"]

    assert eligibility.why_not_mountable(mapping, found) is None
    assert eligibility.bitlocker_container(mapping, found.tree).kname == "sdb1"


def test_a_mapping_on_a_bitlocker_container_follows_the_os_set():
    found = facts(BITLOCKER_TREE, os_parts=UNKNOWN)

    assert eligibility.why_not_mountable(found.tree.devices["dm-0"], found) == (
        "OS partition list unreadable"
    )


def test_a_mapping_on_another_container_is_not_mountable():
    luks = device(
        "sdc1",
        fstype="crypto_LUKS",
        children=[device("dm-1", type="crypt", fstype="ntfs", pkname="sdc1")],
    )
    found = facts(luks)

    assert eligibility.why_not_mountable(found.tree.devices["dm-1"], found) == (
        "unlocked mapping: register its container /dev/sdc1"
    )
    assert eligibility.why_not_mountable(found.tree.devices["sdc1"], found) == (
        "unsupported type crypto_LUKS"
    )
