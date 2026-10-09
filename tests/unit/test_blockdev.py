"""lsblk parsing, removable classification, kname rules and sysfs readers.

Design Doc "blockdev, mounts, naming, escape", Fact Disposition Table row
"deck:/usr/bin/lsblk:device-model" and Headline Finding 3 (parser traps). Every
trap is pinned on the real Deck capture that shows it:

- ``lsblk-columns-tree.json``: the removable chain ``dm-0 -> sdb1 -> sdb``
  (``dm-0`` itself says ``hotplug: false``), ``fstype`` ``BitLocker`` in that
  exact case, the extended partition ``sdb2`` with ``fstype: null``,
  ``mountpoints: []``, and a label with ``/`` in it;
- ``lsblk-columns-list.json``: the same devices in list form (no nesting), so
  removable must come from ``pkname``, not from nesting;
- ``lsblk-full.json``: sizes like ``"238.5G"`` because ``--bytes`` was not
  given, which the parser refuses.

sysfs is real files under ``tmp_path`` built from ``sysfs-facts.txt``.
"""

import json
import os
from typing import Any

import pytest

from steamos_mounter import blockdev
from steamos_mounter.blockdev import (
    KNAME_RE,
    LSBLK_COLUMNS,
    BlockDevice,
    DeviceTree,
    kname_of_syspath,
    parse_lsblk_json,
    read_tree,
    validate_kname,
)
from steamos_mounter.errors import ExitCode, InvalidKernelName, ToolError
from tests.helpers.builders import LSBLK_KEYS, lsblk_device, lsblk_tree
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture
from tests.helpers.host_tree import SysfsDevice

TREE_FIXTURE = "lsblk-columns-tree.json"
LIST_FIXTURE = "lsblk-columns-list.json"
FULL_BYTES_FIXTURE = "lsblk-full-bytes.json"
HUMAN_SIZES_FIXTURE = "lsblk-full.json"
LSBLK = "/usr/bin/lsblk"
DESIGN_COLUMNS = (
    "NAME,KNAME,PATH,MAJ:MIN,TYPE,FSTYPE,FSVER,LABEL,UUID,PTUUID,PTTYPE,PARTUUID,"
    "PARTLABEL,PARTTYPENAME,PKNAME,HOTPLUG,RM,RO,TRAN,SIZE,MOUNTPOINTS"
)
READ_TREE_ARGV = (LSBLK, "--json", "--bytes", "--tree", "-o", DESIGN_COLUMNS)

# Depth-first order of the tree capture.
REAL_KNAMES = (
    "sda",
    "sda1",
    "sdb",
    "sdb1",
    "dm-0",
    "sdb2",
    "sdb5",
    "mmcblk0",
    "mmcblk0p1",
    "zram0",
    "nvme0n1",
    "nvme0n1p1",
    "nvme0n1p2",
    "nvme0n1p3",
    "nvme0n1p4",
    "nvme0n1p5",
    "nvme0n1p6",
    "nvme0n1p7",
    "nvme0n1p8",
)
NVME_PARTITIONS = tuple(f"nvme0n1p{number}" for number in range(1, 9))
REAL_PARENTS = {
    "sda": (),
    "sda1": ("sda",),
    "sdb": (),
    "sdb1": ("sdb",),
    "dm-0": ("sdb1",),
    "sdb2": ("sdb",),
    "sdb5": ("sdb",),
    "mmcblk0": (),
    "mmcblk0p1": ("mmcblk0",),
    "zram0": (),
    "nvme0n1": (),
    **dict.fromkeys(NVME_PARTITIONS, ("nvme0n1",)),
}
PERSONAL_LABEL = "PAT4T4SHUAWEI PERSONAL 4/3/2024"
UDISKS_DM0_NAME = "PAT4T4SHUAWEI_PERSONAL_4_3_2024"

SDB1 = BlockDevice(
    kname="sdb1",
    path="/dev/sdb1",
    devnum="8:17",
    type="part",
    fstype="BitLocker",
    label=PERSONAL_LABEL,
    uuid="658207d5-5177-4a52-a297-31643c64724d",
    partuuid="affac936-01",
    pkname="sdb",
    hotplug=True,
    ro=False,
    size=325803308544,
    mountpoints=(),
    tran=None,
)
DM0 = BlockDevice(
    kname="dm-0",
    path=f"/dev/mapper/{UDISKS_DM0_NAME}",
    devnum="252:0",
    type="crypt",
    fstype="ntfs",
    label="PERSONAL",
    uuid="88D48067D48058F8",
    partuuid=None,
    pkname="sdb1",
    hotplug=False,
    ro=False,
    size=325803308544,
    mountpoints=(),
    tran=None,
)
SDB2 = BlockDevice(
    kname="sdb2",
    path="/dev/sdb2",
    devnum="8:18",
    type="part",
    fstype=None,
    label=None,
    uuid=None,
    partuuid="affac936-02",
    pkname="sdb",
    hotplug=True,
    ro=False,
    size=1024,
    mountpoints=(),
    tran=None,
)
SDB5 = BlockDevice(
    kname="sdb5",
    path="/dev/sdb5",
    devnum="8:21",
    type="part",
    fstype="ntfs",
    label="MEDIABOX",
    uuid="01D95F1575592A30",
    partuuid="affac936-05",
    pkname="sdb",
    hotplug=True,
    ro=False,
    size=674398900224,
    mountpoints=(),
    tran=None,
)
SDB = BlockDevice(
    kname="sdb",
    path="/dev/sdb",
    devnum="8:16",
    type="disk",
    fstype=None,
    label=None,
    uuid=None,
    partuuid=None,
    pkname=None,
    hotplug=True,
    ro=False,
    size=1000204886016,
    mountpoints=(),
    tran="usb",
)
SDA1 = BlockDevice(
    kname="sda1",
    path="/dev/sda1",
    devnum="8:1",
    type="part",
    fstype="ext4",
    label="EXT256",
    uuid="4af5710c-af99-491b-b8dd-e3050268b8be",
    partuuid="5cfa4eac-4d43-48af-ace6-aeba544411a7",
    pkname="sda",
    hotplug=True,
    ro=False,
    size=256016409600,
    mountpoints=("/run/media/deck/EXT256",),
    tran=None,
)
HOME_MOUNTPOINTS = (
    "/var/tmp",
    "/var/lib/systemd/coredump",
    "/var/log",
    "/var/lib/steamos-log-submitter",
    "/var/lib/flatpak",
    "/var/lib/docker",
    "/var/cache/pacman",
    "/nix",
    "/opt",
    "/root",
    "/srv",
    "/home",
)


def real_tree() -> DeviceTree:
    return parse_lsblk_json(load_fixture(TREE_FIXTURE))


def tree_of(*devices: dict[str, Any]) -> DeviceTree:
    return parse_lsblk_json(json.dumps(lsblk_tree(devices)).encode("utf-8"))


def load(name: str) -> DeviceTree:
    return parse_lsblk_json(load_fixture(name))


# --- constants ---------------------------------------------------------------


def test_lsblk_columns_match_the_design_doc():
    assert LSBLK_COLUMNS == DESIGN_COLUMNS


def test_lsblk_columns_are_the_json_keys_the_builders_write():
    keys = tuple(column.lower() for column in LSBLK_COLUMNS.split(","))

    assert keys == LSBLK_KEYS


def test_kname_re_is_the_ac030_pattern():
    assert KNAME_RE.pattern == r"^[a-z0-9-]+$"


# --- read_tree ---------------------------------------------------------------


def test_read_tree_runs_one_lsblk_call_with_the_shared_columns(ctx, fake_runner):
    fake_runner.on(LSBLK, TREE_FIXTURE)

    tree = read_tree(ctx)

    assert fake_runner.argvs == [READ_TREE_ARGV]
    assert tuple(tree.devices) == REAL_KNAMES


@pytest.mark.parametrize(
    "answer",
    [
        Answer(returncode=1, stderr=b"lsblk: failed to access sysfs directory"),
        Answer.timeout(),
        Answer.missing(),
    ],
    ids=["exit-1", "timeout", "not-found"],
)
def test_read_tree_failure_is_a_tool_error(ctx, fake_runner, answer):
    fake_runner.on(LSBLK, answer)

    with pytest.raises(ToolError) as caught:
        read_tree(ctx)

    assert caught.value.exit_code == ExitCode.FAILED
    assert caught.value.user_message == "cannot list block devices"


# --- golden tree -------------------------------------------------------------


def test_golden_tree_has_every_device_in_depth_first_order():
    tree = real_tree()

    assert tuple(tree.devices) == REAL_KNAMES


def test_golden_tree_parents_follow_the_nesting():
    assert dict(real_tree().parents) == REAL_PARENTS


@pytest.mark.parametrize("expected", [SDB, SDB1, DM0, SDB2, SDB5, SDA1], ids=str)
def test_golden_tree_devices(expected):
    assert real_tree().devices[expected.kname] == expected


def test_golden_tree_keeps_every_mountpoint_of_the_home_partition():
    assert real_tree().devices["nvme0n1p8"].mountpoints == HOME_MOUNTPOINTS


def test_bitlocker_fstype_keeps_its_exact_case():
    assert real_tree().devices["sdb1"].fstype == "BitLocker"


def test_extended_partition_has_no_fstype():
    sdb2 = real_tree().devices["sdb2"]

    assert sdb2.fstype is None
    assert sdb2.uuid is None


def test_empty_mountpoints_list_is_an_empty_tuple():
    assert real_tree().devices["sdb5"].mountpoints == ()


def test_null_mountpoint_entries_are_dropped():
    tree = tree_of(lsblk_device("sdc1", {"mountpoints": [None]}))

    assert tree.devices["sdc1"].mountpoints == ()


def test_label_with_slash_is_kept_verbatim():
    assert real_tree().devices["sdb1"].label == PERSONAL_LABEL


def test_list_form_gives_the_same_devices_without_parents():
    listed = load(LIST_FIXTURE)
    tree = real_tree()

    assert dict(listed.devices) == dict(tree.devices)
    assert set(listed.parents.values()) == {()}


def test_full_capture_with_extra_columns_parses_to_the_same_devices():
    assert dict(load(FULL_BYTES_FIXTURE).devices) == dict(real_tree().devices)


def test_human_readable_sizes_are_refused():
    with pytest.raises(ToolError):
        load(HUMAN_SIZES_FIXTURE)


def test_undecodable_label_bytes_survive_as_surrogates():
    document = json.dumps(lsblk_tree([lsblk_device("sdc1", {"label": "MÉDIA"})]))
    raw = document.encode("utf-8").replace(b"\\u00c9", b"\xff")

    tree = parse_lsblk_json(raw)

    assert tree.devices["sdc1"].label == "M\udcffDIA"


def test_a_device_nested_twice_is_listed_once_with_both_parents():
    member = lsblk_device("dm-2", {"type": "crypt"})
    tree = tree_of(
        lsblk_device("sdc", {"type": "disk", "children": [member]}),
        lsblk_device("sdd", {"type": "disk", "children": [member]}),
    )

    assert tuple(tree.devices) == ("sdc", "dm-2", "sdd")
    assert tree.parents["dm-2"] == ("sdc", "sdd")


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not json",
        b"[]",
        b'{"devices": []}',
        b'{"blockdevices": {}}',
        b'{"blockdevices": [1]}',
    ],
    ids=["empty", "not-json", "not-object", "no-blockdevices", "not-list", "not-node"],
)
def test_malformed_document_is_a_tool_error(data):
    with pytest.raises(ToolError):
        parse_lsblk_json(data)


@pytest.mark.parametrize(
    "columns",
    [
        {"hotplug": "1"},
        {"ro": None},
        {"size": "1024"},
        {"size": True},
        {"kname": None},
        {"maj:min": None},
        {"fstype": 7},
        {"mountpoints": "/run/media/deck/X"},
        {"mountpoints": [7]},
        {"children": {}},
    ],
    ids=repr,
)
def test_wrong_column_type_is_a_tool_error(columns):
    with pytest.raises(ToolError):
        tree_of(lsblk_device("sdc1", columns))


@pytest.mark.parametrize("missing", LSBLK_KEYS)
def test_missing_requested_column_is_a_tool_error(missing):
    device = lsblk_device("sdc1")
    del device[missing]

    with pytest.raises(ToolError) as caught:
        tree_of(device)

    assert missing in caught.value.detail


# --- removable chain ---------------------------------------------------------


def test_dm0_reports_no_hotplug_itself():
    assert real_tree().devices["dm-0"].hotplug is False


def test_removable_chain_reaches_the_usb_disk_through_pkname():
    tree = real_tree()

    assert tree.top_disk("dm-0") == SDB
    assert tree.is_removable("dm-0") is True


@pytest.mark.parametrize("kname", ["sdb", "sdb1", "sdb2", "sdb5", "sda1", "mmcblk0p1"])
def test_external_devices_are_removable(kname):
    assert real_tree().is_removable(kname) is True


@pytest.mark.parametrize("kname", ["zram0", "nvme0n1", *NVME_PARTITIONS])
def test_internal_devices_are_not_removable(kname):
    assert real_tree().is_removable(kname) is False


def test_list_form_reaches_the_same_top_disk():
    assert load(LIST_FIXTURE).top_disk("dm-0") == SDB


def test_unknown_device_cannot_be_classified():
    tree = real_tree()

    assert tree.top_disk("sdz9") is None
    assert tree.is_removable("sdz9") is None


def test_broken_pkname_chain_cannot_be_classified():
    tree = tree_of(lsblk_device("dm-3", {"type": "crypt", "pkname": "sdq1"}))

    assert tree.top_disk("dm-3") is None
    assert tree.is_removable("dm-3") is None


def test_pkname_cycle_cannot_be_classified():
    tree = tree_of(
        lsblk_device("dm-4", {"pkname": "dm-5", "hotplug": True}),
        lsblk_device("dm-5", {"pkname": "dm-4", "hotplug": True}),
    )

    assert tree.top_disk("dm-4") is None
    assert tree.is_removable("dm-4") is None


# --- by_uuid -----------------------------------------------------------------


def test_by_uuid_finds_the_one_device():
    assert real_tree().by_uuid("01D95F1575592A30") == (SDB5,)


def test_by_uuid_ignores_case():
    assert real_tree().by_uuid("01d95f1575592a30") == (SDB5,)


def test_by_uuid_returns_every_duplicate_in_tree_order():
    tree = tree_of(
        lsblk_device("sdc1", {"uuid": "1234-ABCD", "fstype": "exfat"}),
        lsblk_device("sdd1", {"uuid": "5678-0000", "fstype": "exfat"}),
        lsblk_device("sde1", {"uuid": "1234-abcd", "fstype": "exfat"}),
    )

    found = tree.by_uuid("1234-ABCD")

    assert tuple(device.kname for device in found) == ("sdc1", "sde1")


def test_by_uuid_unknown_is_empty():
    assert real_tree().by_uuid("0000-0000") == ()


# --- synthetic trees ---------------------------------------------------------

SYNTHETIC_TREES = {
    "lsblk-tree-with-exfat-sdc1.json": (),
    "lsblk-tree-with-ntfs-sdc1.json": (),
    "lsblk-tree-dolphin-unregistered.json": (),
    "lsblk-tree-personal-locked.json": ("dm-0",),
}


@pytest.mark.parametrize("name", sorted(SYNTHETIC_TREES))
def test_synthetic_tree_keeps_every_real_device_unchanged(name):
    removed = SYNTHETIC_TREES[name]
    real = real_tree()

    synthetic = load(name)

    for kname in REAL_KNAMES:
        if kname in removed:
            assert kname not in synthetic.devices
            continue
        assert synthetic.devices[kname] == real.devices[kname]


@pytest.mark.parametrize(
    ("name", "fstype", "label", "uuid"),
    [
        ("lsblk-tree-with-exfat-sdc1.json", "exfat", "GAMES", "1234-ABCD"),
        ("lsblk-tree-with-ntfs-sdc1.json", "ntfs", "MOVIES", "2AB4C1D5E6F70819"),
        (
            "lsblk-tree-dolphin-unregistered.json",
            "BitLocker",
            "OBAMA BACKUP 1/2/2025",
            "7c1e4b2a-9d3f-4e5a-8b6c-0d1e2f3a4b5c",
        ),
    ],
)
def test_synthetic_sdc1_is_a_removable_usb_partition(name, fstype, label, uuid):
    tree = load(name)

    sdc1 = tree.devices["sdc1"]

    assert (sdc1.fstype, sdc1.label, sdc1.uuid) == (fstype, label, uuid)
    assert (sdc1.devnum, sdc1.pkname) == ("8:33", "sdc")
    assert tree.parents["sdc1"] == ("sdc",)
    assert tree.top_disk("sdc1").tran == "usb"
    assert tree.is_removable("sdc1") is True


def test_dolphin_tree_has_a_foreign_mapping_on_sdc1():
    tree = load("lsblk-tree-dolphin-unregistered.json")

    dm1 = tree.devices["dm-1"]

    assert dm1.type == "crypt"
    assert (dm1.fstype, dm1.label, dm1.uuid) == ("ntfs", "OBAMA", "3C5E7A9B1D2F4E60")
    assert (dm1.devnum, dm1.pkname, dm1.hotplug) == ("252:1", "sdc1", False)
    assert dm1.path == "/dev/mapper/OBAMA_BACKUP_1_2_2025"
    assert tree.parents["dm-1"] == ("sdc1",)
    assert tree.is_removable("dm-1") is True


def test_locked_tree_has_no_mapping_on_sdb1():
    tree = load("lsblk-tree-personal-locked.json")

    assert tree.devices["sdb1"] == SDB1
    assert all("sdb1" not in parents for parents in tree.parents.values())


# --- validate_kname (AC-030) ------------------------------------------------


@pytest.mark.parametrize(
    "kname", ["sda", "sdb1", "dm-0", "nvme0n1p8", "mmcblk0p1", "loop0", "zram0"]
)
def test_validate_kname_accepts_kernel_names(kname):
    assert validate_kname(kname) == kname


@pytest.mark.parametrize(
    "kname",
    [
        "",
        "SDB",
        "sdb/1",
        "../sdb",
        "..",
        "sdb1\n",
        "sd b",
        "dm_0",
        "sdé",
        "sdb1;reboot",
        "\x00",
    ],
    ids=repr,
)
def test_validate_kname(kname):
    with pytest.raises(InvalidKernelName) as caught:
        validate_kname(kname)

    assert caught.value.exit_code == ExitCode.FAILED
    assert str(caught.value) == "invalid kernel device name"
    assert repr(kname) in caught.value.detail


# --- kname_of_syspath --------------------------------------------------------


@pytest.mark.parametrize(
    ("syspath", "kname"),
    [
        ("/sys/devices/virtual/block/dm-0", "dm-0"),
        (
            "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-2/2-2:1.0/host1/"
            "target1:0:0/1:0:0:0/block/sdc/sdc1",
            "sdc1",
        ),
        ("/sys/devices/platform/mmc/block/mmcblk0/mmcblk0p1", "mmcblk0p1"),
    ],
)
def test_kname_of_syspath_is_the_last_component(syspath, kname):
    assert kname_of_syspath(syspath) == kname


@pytest.mark.parametrize(
    "syspath",
    [
        "/sys/devices/virtual/block/dm-0/",
        "/sys/devices/virtual/block/DM-0",
        "/sys/devices/virtual/block/..",
        "",
    ],
    ids=repr,
)
def test_kname_of_syspath_rejects_a_bad_last_component(syspath):
    with pytest.raises(InvalidKernelName):
        kname_of_syspath(syspath)


# --- sysfs readers (real files under tmp_path) -------------------------------


@pytest.fixture
def deck_sysfs(host_tree):
    host_tree.add_sysfs_facts()
    return host_tree


def test_slaves_of_dm0_is_its_container(ctx, deck_sysfs):
    assert blockdev.slaves(ctx, "dm-0") == ("sdb1",)


def test_holders_of_sdb1_is_its_mapping(ctx, deck_sysfs):
    assert blockdev.holders(ctx, "sdb1") == ("dm-0",)


def test_holders_of_an_unheld_partition_is_empty(ctx, deck_sysfs):
    assert blockdev.holders(ctx, "sdb5") == ()


def test_listing_is_sorted(ctx, host_tree):
    host_tree.add_block(SysfsDevice(kname="sdc1", devnum="8:33"))
    host_tree.add_block(SysfsDevice(kname="sdd1", devnum="8:49"))
    host_tree.add_block(SysfsDevice(kname="md0", slaves=("sdd1", "sdc1")))

    assert blockdev.slaves(ctx, "md0") == ("sdc1", "sdd1")


def test_dm_name_of_dm0_is_the_udisks_name(ctx, deck_sysfs):
    assert blockdev.dm_name(ctx, "dm-0") == UDISKS_DM0_NAME


def test_dm_name_keeps_inner_spaces(ctx, host_tree):
    host_tree.add_block(SysfsDevice(kname="dm-1", dm_name="OBAMA BACKUP "))

    assert blockdev.dm_name(ctx, "dm-1") == "OBAMA BACKUP "


def test_dm_name_of_a_partition_is_none(ctx, deck_sysfs):
    assert blockdev.dm_name(ctx, "sdb1") is None


@pytest.mark.parametrize(
    ("kname", "expected"), [("sdb1", "8:17"), ("sdb5", "8:21"), ("dm-0", "252:0")]
)
def test_devnum_reads_the_dev_attribute(ctx, deck_sysfs, kname, expected):
    assert blockdev.devnum(ctx, kname) == expected


def test_devnum_without_a_dev_attribute_is_none(ctx, deck_sysfs):
    assert blockdev.devnum(ctx, "sdb") is None


@pytest.mark.parametrize(
    ("kname", "expected"),
    [
        ("dm-0", "/sys/devices/virtual/block/dm-0"),
        ("sdb", "/sys/devices/host-tree/block/sdb"),
        ("sdb5", "/sys/devices/host-tree/block/sdb/sdb5"),
    ],
)
def test_syspath_is_the_canonical_directory(ctx, deck_sysfs, kname, expected):
    assert blockdev.syspath(ctx, kname) == expected


def test_syspath_leaving_the_root_is_none(ctx, tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    link = tmp_path / "sys/class/block/sdx"
    link.parent.mkdir(parents=True)
    link.symlink_to(os.path.relpath(outside, link.parent))

    assert blockdev.syspath(ctx, "sdx") is None


@pytest.mark.parametrize(
    "reader",
    [blockdev.slaves, blockdev.holders],
    ids=["slaves", "holders"],
)
def test_listing_of_an_absent_device_is_empty(ctx, deck_sysfs, reader):
    assert reader(ctx, "sdz9") == ()


@pytest.mark.parametrize(
    "reader",
    [blockdev.dm_name, blockdev.devnum, blockdev.syspath],
    ids=["dm_name", "devnum", "syspath"],
)
def test_attribute_of_an_absent_device_is_none(ctx, deck_sysfs, reader):
    assert reader(ctx, "sdz9") is None


@pytest.mark.parametrize(
    "reader",
    [
        blockdev.slaves,
        blockdev.holders,
        blockdev.dm_name,
        blockdev.devnum,
        blockdev.syspath,
    ],
    ids=["slaves", "holders", "dm_name", "devnum", "syspath"],
)
def test_sysfs_readers_refuse_a_bad_kname(ctx, deck_sysfs, reader):
    with pytest.raises(InvalidKernelName):
        reader(ctx, "../../etc")
