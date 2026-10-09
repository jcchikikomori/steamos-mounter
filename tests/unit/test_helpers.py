"""Self-tests for the shared test helpers under tests/helpers/.

Design Doc: docs/design/steamos-mounter-design.md (sections "Test Boundaries >
Mock Boundary Decisions", "Data Layer Testing Strategy", "Fixtures", "doctor
Keep-list Check (Authoritative)" and "Keep-list Drop-in (Authoritative)").
The helpers are what later tests stand on, so each one is checked against real
files: the Deck captures, real directories and symlinks under tmp_path, and the
real /usr/bin/rsync for the keep-list replay.
"""

import json
import os
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.contract import test_fixtures
from tests.contract.test_python import imported_top_levels
from tests.helpers import builders, fixtures, rsync_replay
from tests.helpers.clock import FakeClock
from tests.helpers.fixtures import fixture_rc, load_fixture, strip_synthetic_header
from tests.helpers.host_tree import HostTree, SysfsDevice, parse_sysfs_facts

HELPERS = Path(__file__).resolve().parents[1] / "helpers"

# Design Doc "Keep-list Drop-in (Authoritative)", data/steamos-mounter.conf.
OUR_DROPIN = """\
## steamos-mounter: keep its /etc files across SteamOS atomic updates.
## Installed and removed by steamos-mounter. Do not edit.
/etc/atomic-update.conf.d/steamos-mounter.conf
/etc/steamos-mounter/**
/etc/udev/rules.d/90-steamos-mounter.rules
/etc/systemd/system/steamos-mounter@.service
/etc/systemd/system/steamos-mounter-auto@.service
/etc/systemd/system/steamos-mounter-key@.service
/etc/systemd/system/*.device.wants/steamos-mounter@*.service
"""
UNIT_TEMPLATE = "/etc/systemd/system/steamos-mounter@.service"
MEDIABOX_LINK = (
    "/etc/systemd/system/dev-disk-by\\x2duuid-01D95F1575592A30.device.wants/"
    "steamos-mounter@dev-disk-by\\x2duuid-01D95F1575592A30.service"
)
PERSONAL_LINK = (
    "/etc/systemd/system/"
    "dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52\\x2da297\\x2d31643c64724d"
    ".device.wants/steamos-mounter@"
    "dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52\\x2da297\\x2d31643c64724d"
    ".service"
)
# The installed /etc paths the review's replay checked (verify/rsync_doctor_check.py).
INSTALLED_ETC = {
    "/etc/atomic-update.conf.d/steamos-mounter.conf": None,
    "/etc/steamos-mounter/config.toml": None,
    "/etc/udev/rules.d/90-steamos-mounter.rules": None,
    UNIT_TEMPLATE: None,
    "/etc/systemd/system/steamos-mounter-auto@.service": None,
    "/etc/systemd/system/steamos-mounter-key@.service": None,
    MEDIABOX_LINK: UNIT_TEMPLATE,
    PERSONAL_LINK: UNIT_TEMPLATE,
}

# The emitter's header line is longer than 88 columns, so it is joined here.
REGISTRY_HEADER = (
    "# steamos-mounter registry. Managed by steamos-mounter: "
    "comments and formatting are not kept.\n"
)
REGISTRY_EXAMPLE = (
    REGISTRY_HEADER
    + """\
schema_version = 1

[[volume]]
name = "MEDIABOX"
uuid = "01D95F1575592A30"
path = "/run/media/deck/MEDIABOX"
fstype = "ntfs"
nosuid = true
nodev = true

[[volume]]
name = "PERSONAL"
uuid = "658207d5-5177-4a52-a297-31643c64724d"
path = "/run/media/deck/PERSONAL"
fstype = "BitLocker"
drivers = ["ntfs3", "ntfs-3g", "ntfs3:ro"]
nosuid = true
nodev = true
"""
)

LSBLK_KEYS = {
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
}


def all_conf_dropin() -> str:
    """Valve's example drop-in without the '### <path>' line the capture added."""
    text = load_fixture("atomic-update.conf.d-all.conf").decode("utf-8")
    return text.split("\n", 1)[1]


@pytest.fixture
def fixture_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Point the loader at an empty deck/ and synthetic/ pair under tmp_path."""
    deck = tmp_path / "deck"
    synthetic = tmp_path / "synthetic"
    deck.mkdir()
    synthetic.mkdir()
    monkeypatch.setattr(fixtures, "DECK", deck)
    monkeypatch.setattr(fixtures, "SYNTHETIC", synthetic)
    return deck, synthetic


# --- fixtures.py -------------------------------------------------------------


def test_load_fixture_returns_a_deck_capture_verbatim():
    data = load_fixture("sysfs-facts.txt")

    assert data.startswith(b"/sys/block/dm-0/dev=252:0\n")
    assert data.endswith(b"/sys/class/block/sdb5/holders=\n")


def test_load_fixture_reads_evidence_by_relative_name():
    data = load_fixture("evidence/evidence-blockdev-event-partsets.txt")

    assert len(data) > 0


def test_load_fixture_strips_the_synthetic_header_so_json_parses(fixture_dirs):
    _, synthetic = fixture_dirs
    (synthetic / "findmnt-x.json").write_bytes(
        b'# synthetic: findmnt read-back of a fuseblk mount\n{"filesystems": []}\n'
    )

    data = load_fixture("findmnt-x.json")

    assert data == b'{"filesystems": []}\n'
    assert json.loads(data) == {"filesystems": []}


def test_load_fixture_prefers_deck_over_synthetic(fixture_dirs):
    deck, synthetic = fixture_dirs
    (deck / "same.txt").write_bytes(b"real capture\n")
    (synthetic / "same.txt").write_bytes(b"# synthetic: stand-in\nfake\n")

    assert load_fixture("same.txt") == b"real capture\n"


def test_load_fixture_keeps_a_deck_first_line_that_looks_synthetic(fixture_dirs):
    deck, _ = fixture_dirs
    (deck / "odd.txt").write_bytes(b"# synthetic: not stripped in deck/\nbody\n")

    assert load_fixture("odd.txt") == b"# synthetic: not stripped in deck/\nbody\n"


def test_load_fixture_raises_for_an_unknown_name(fixture_dirs):
    with pytest.raises(FileNotFoundError, match=r"no-such-capture\.txt"):
        load_fixture("no-such-capture.txt")


def test_strip_synthetic_header_removes_only_the_first_line():
    data = b"# synthetic: why\nline 1\n# synthetic: stays\n"

    assert strip_synthetic_header(data) == b"line 1\n# synthetic: stays\n"


def test_strip_synthetic_header_leaves_unlabeled_bytes_alone():
    assert strip_synthetic_header(b"plain\n") == b"plain\n"


def test_strip_synthetic_header_of_a_header_only_file_is_empty():
    assert strip_synthetic_header(b"# synthetic: empty output") == b""


def test_loader_header_agrees_with_the_fixture_contract():
    assert fixtures.SYNTHETIC_HEADER == test_fixtures.SYNTHETIC_HEADER


@pytest.mark.parametrize(
    ("name", "rc"),
    [
        ("findmnt-sdb5-not-mounted.json", 1),
        ("findmnt-dm-0-not-mounted.json", 1),
        ("efi-partsets-all.txt", 1),
        ("lsblk-full.json", 0),
        ("evidence-locale-diff-lsblk.txt", 0),
        ("evidence/evidence-locale-diff-lsblk.txt", 0),
    ],
)
def test_fixture_rc_reads_the_capture_index(name, rc):
    assert fixture_rc(name) == rc


def test_fixture_rc_raises_for_a_name_without_an_index_row():
    with pytest.raises(KeyError, match=r"not-captured\.json"):
        fixture_rc("not-captured.json")


# --- clock.py ----------------------------------------------------------------


def test_fake_clock_starts_at_fixed_utc_and_monotonic_values():
    clock = FakeClock()

    assert clock.now() == datetime(2026, 10, 8, 2, 11, 40, tzinfo=UTC)
    assert clock.monotonic() == 1000.0


def test_fake_clock_advance_moves_both_clocks_together():
    clock = FakeClock()

    clock.advance(120.5)

    assert clock.monotonic() == 1120.5
    assert clock.now() == datetime(2026, 10, 8, 2, 13, 40, 500000, tzinfo=UTC)


def test_fake_clock_accepts_a_custom_start():
    clock = FakeClock(start=datetime(2030, 1, 1, tzinfo=UTC), monotonic_start=5.0)

    clock.advance(60)

    assert clock.now() == datetime(2030, 1, 1, 0, 1, tzinfo=UTC)
    assert clock.monotonic() == 65.0


def test_fake_clock_advance_zero_keeps_the_time():
    clock = FakeClock()

    clock.advance(0)

    assert clock.monotonic() == 1000.0


def test_fake_clock_refuses_to_go_backwards():
    clock = FakeClock()

    with pytest.raises(ValueError, match="backwards"):
        clock.advance(-0.001)
    assert clock.monotonic() == 1000.0


def test_fake_clock_refuses_a_naive_start():
    with pytest.raises(ValueError, match="timezone"):
        FakeClock(start=datetime(2026, 10, 8))


def test_fake_clock_now_is_timezone_aware():
    assert FakeClock().now().utcoffset() == timedelta(0)


def test_fake_clock_fixture_is_a_fresh_fake_clock(fake_clock):
    assert isinstance(fake_clock, FakeClock)
    assert fake_clock.monotonic() == 1000.0


# --- host_tree.py ------------------------------------------------------------


def read_attr(root: Path, absolute: str) -> str:
    return (root / absolute.lstrip("/")).read_text(encoding="utf-8")


def listing(root: Path, absolute: str) -> list[str]:
    return sorted(os.listdir(root / absolute.lstrip("/")))


def resolved(root: Path, absolute: str) -> Path:
    return (root / absolute.lstrip("/")).resolve()


def test_parse_sysfs_facts_groups_the_deck_facts_by_kname():
    devices = {device.kname: device for device in parse_sysfs_facts()}

    assert set(devices) == {"dm-0", "sdb", "sda", "mmcblk0", "nvme0n1", "sdb1", "sdb5"}
    assert devices["dm-0"] == SysfsDevice(
        kname="dm-0",
        devnum="252:0",
        slaves=("sdb1",),
        dm_name="PAT4T4SHUAWEI_PERSONAL_4_3_2024",
        attributes={"dm/uuid": "CRYPT-BITLK-PAT4T4SHUAWEI_PERSONAL_4_3_2024"},
    )
    assert devices["sdb1"] == SysfsDevice(
        kname="sdb1",
        devnum="8:17",
        parent="sdb",
        holders=("dm-0",),
        attributes={"partition": "1"},
    )
    assert devices["sdb5"].holders == ()
    assert devices["sdb"].attributes == {"removable": "0"}


@pytest.mark.parametrize(
    ("kname", "parent"),
    [
        ("sdb5", "sdb"),
        ("sdp12", "sdp"),
        ("mmcblk0p1", "mmcblk0"),
        ("nvme0n1p8", "nvme0n1"),
    ],
)
def test_parse_sysfs_facts_names_the_whole_disk_of_a_partition(kname, parent):
    (device,) = parse_sysfs_facts(f"/sys/class/block/{kname}/partition=1\n")

    assert device.parent == parent


@pytest.mark.parametrize(
    "line",
    ["/sys/block/sdb/removable", "/proc/mounts=x", "/sys/class/block/=1"],
)
def test_parse_sysfs_facts_rejects_a_malformed_line(line):
    with pytest.raises(ValueError, match="sysfs fact"):
        parse_sysfs_facts(line + "\n")


def test_host_tree_from_deck_facts_has_dev_and_dm_name_files(host_tree):
    host_tree.add_sysfs_facts()
    root = host_tree.root

    assert read_attr(root, "/sys/block/dm-0/dev") == "252:0\n"
    assert read_attr(root, "/sys/block/dm-0/dm/name") == (
        "PAT4T4SHUAWEI_PERSONAL_4_3_2024\n"
    )
    assert read_attr(root, "/sys/class/block/dm-0/dm/name") == (
        "PAT4T4SHUAWEI_PERSONAL_4_3_2024\n"
    )
    assert read_attr(root, "/sys/class/block/sdb5/start") == "636334713\n"
    assert read_attr(root, "/sys/block/sdb/removable") == "0\n"


def test_host_tree_from_deck_facts_has_slaves_and_holders(host_tree):
    host_tree.add_sysfs_facts()
    root = host_tree.root

    assert listing(root, "/sys/class/block/dm-0/slaves") == ["sdb1"]
    assert listing(root, "/sys/class/block/sdb1/holders") == ["dm-0"]
    assert listing(root, "/sys/class/block/sdb5/holders") == []
    assert listing(root, "/sys/class/block/sdb1/slaves") == []
    assert resolved(root, "/sys/class/block/dm-0/slaves/sdb1") == resolved(
        root, "/sys/class/block/sdb1"
    )


def test_host_tree_dev_block_links_resolve_to_the_device(host_tree):
    host_tree.add_sysfs_facts()
    root = host_tree.root

    assert resolved(root, "/sys/dev/block/8:17") == resolved(
        root, "/sys/class/block/sdb1"
    )
    assert resolved(root, "/sys/dev/block/252:0") == resolved(root, "/sys/block/dm-0")
    assert resolved(root, "/sys/block/dm-0") == root / "sys/devices/virtual/block/dm-0"


def test_host_tree_puts_partitions_under_their_disk_only(host_tree):
    host_tree.add_sysfs_facts()
    root = host_tree.root

    assert resolved(root, "/sys/class/block/sdb5").parent == resolved(
        root, "/sys/block/sdb"
    )
    assert not (root / "sys/block/sdb5").exists()


def test_host_tree_links_are_relative_and_stay_inside_the_root(host_tree):
    host_tree.add_sysfs_facts()
    root = host_tree.root

    links = [path for path in root.rglob("*") if path.is_symlink()]

    assert len(links) > 0
    assert all(not os.readlink(link).startswith("/") for link in links)
    assert all(link.resolve().is_relative_to(root) for link in links)


def test_host_tree_uses_a_given_syspath(host_tree):
    syspath = "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-1/block/sdc/sdc1"

    made = host_tree.add_block(
        SysfsDevice(kname="sdc1", devnum="8:33", parent="sdc", syspath=syspath)
    )

    assert made == host_tree.root / syspath.lstrip("/")
    assert resolved(host_tree.root, "/sys/dev/block/8:33") == made
    assert read_attr(host_tree.root, "/sys/class/block/sdc1/dev") == "8:33\n"


def test_host_tree_block_without_devnum_has_no_dev_link(host_tree):
    host_tree.add_block(SysfsDevice(kname="sdd"))

    assert not (host_tree.root / "sys/class/block/sdd/dev").exists()
    assert not (host_tree.root / "sys/dev/block").exists()
    assert listing(host_tree.root, "/sys/block/sdd/holders") == []


def test_host_tree_by_uuid_link_points_at_the_device_node(host_tree):
    link = host_tree.link_by_uuid("01D95F1575592A30", "sdb5")

    assert link == host_tree.root / "dev/disk/by-uuid/01D95F1575592A30"
    assert os.readlink(link) == "../../sdb5"
    assert link.resolve() == host_tree.root / "dev/sdb5"
    assert link.exists()


def test_host_tree_by_partsets_link_points_at_the_device_node(host_tree):
    link = host_tree.link_by_partsets("home", "nvme0n1p8")

    assert link == host_tree.root / "dev/disk/by-partsets/all/home"
    assert os.readlink(link) == "../../../nvme0n1p8"
    assert link.resolve() == host_tree.root / "dev/nvme0n1p8"


def test_host_tree_two_links_can_share_a_device_node(host_tree):
    first = host_tree.link_by_uuid("AAAA-BBBB", "sdc1")
    second = host_tree.link_by_partsets("esp", "sdc1")

    assert first.resolve() == second.resolve()


def test_host_tree_path_maps_absolute_paths_under_the_root(host_tree):
    assert (
        host_tree.path("/etc/steamos-mounter") == host_tree.root / "etc/steamos-mounter"
    )


def test_host_tree_fixture_is_rooted_at_tmp_path(host_tree, tmp_path):
    assert isinstance(host_tree, HostTree)
    assert host_tree.root == tmp_path


# --- builders.py -------------------------------------------------------------


def test_registry_text_matches_the_design_doc_example():
    text = builders.registry_text((builders.PERSONAL, builders.MEDIABOX))

    assert text == REGISTRY_EXAMPLE


def test_registry_text_parses_as_toml():
    parsed = tomllib.loads(builders.registry_text((builders.MEDIABOX,)))

    assert parsed == {
        "schema_version": 1,
        "volume": [
            {
                "name": "MEDIABOX",
                "uuid": "01D95F1575592A30",
                "path": "/run/media/deck/MEDIABOX",
                "fstype": "ntfs",
                "nosuid": True,
                "nodev": True,
            }
        ],
    }


def test_registry_text_without_volumes_is_header_and_version_only():
    text = builders.registry_text(())

    assert text.splitlines()[1:] == ["schema_version = 1"]


def test_registry_text_escapes_strings_like_the_emitter():
    volume = builders.RegistryVolume(
        name="odd",
        uuid="AAAA-BBBB",
        path='/run/media/deck/a"b\\c\x01d\x7f',
        fstype="exfat",
        nosuid=False,
    )

    text = builders.registry_text((volume,))

    assert 'path = "/run/media/deck/a\\"b\\\\c\\u0001d\\u007F"' in text
    assert "nosuid = false" in text
    assert tomllib.loads(text)["volume"][0]["path"] == volume.path


def test_record_dict_is_the_design_doc_example_by_default():
    record = builders.record_dict()

    assert record["format"] == 1
    assert record["kind"] == "registered"
    assert record["key"] == "658207d5-5177-4a52-a297-31643c64724d"
    assert record["state"] == "MountedRWDirty"
    assert record["source"] == {
        "kname": "sdb1",
        "devnum": "8:17",
        "syspath": "/sys/devices/pci0000:00/.../block/sdb/sdb1",
    }
    assert record["mapping"]["devnum"] == "252:0"
    assert record["busy"] == []


def test_record_dict_applies_top_level_changes():
    record = builders.record_dict(state="NotPresent", mapping=None)

    assert record["state"] == "NotPresent"
    assert record["mapping"] is None
    assert record["name"] == "PERSONAL"


def test_record_dict_returns_independent_copies():
    first = builders.record_dict()
    first["mount"]["status"] = "unmounted"

    assert builders.record_dict()["mount"]["status"] == "mounted"


def test_record_dict_is_json_serialisable():
    assert json.loads(json.dumps(builders.record_dict()))["format"] == 1


def test_record_dict_rejects_an_unknown_field():
    with pytest.raises(KeyError, match="mapping_name"):
        builders.record_dict(mapping_name="x")


def test_lsblk_device_has_every_lsblk_column():
    device = builders.lsblk_device("sdc1")

    assert set(device) == LSBLK_KEYS
    assert device["name"] == "sdc1"
    assert device["kname"] == "sdc1"
    assert device["path"] == "/dev/sdc1"
    assert device["mountpoints"] == []


def test_lsblk_device_applies_columns_and_children():
    child = builders.lsblk_device("sdc1", {"fstype": "exfat", "pkname": "sdc"})

    disk = builders.lsblk_device("sdc", {"type": "disk", "children": [child]})

    assert disk["type"] == "disk"
    assert disk["children"][0]["fstype"] == "exfat"


def test_lsblk_device_rejects_an_unknown_column():
    with pytest.raises(KeyError, match="mountpoint"):
        builders.lsblk_device("sdc1", {"mountpoint": "/x"})


def test_lsblk_tree_matches_the_deck_capture_shape():
    deck = json.loads(load_fixture("lsblk-columns-tree.json"))

    tree = builders.lsblk_tree([builders.lsblk_device("sdc")])

    assert set(tree) == set(deck) == {"blockdevices"}
    assert set(tree["blockdevices"][0]) == set(deck["blockdevices"][0]) - {"children"}


# --- rsync_replay.py ---------------------------------------------------------


def test_replay_module_imports_nothing_from_the_package():
    source = (HELPERS / "rsync_replay.py").read_text(encoding="utf-8")

    assert "steamos_mounter" not in imported_top_levels(source)


def test_build_filter_strips_etc_like_holo_sync_var():
    keep = "## keep\n/etc/a\n"
    dropins = ["/etc/b\n\n", "x/etc/c\n/etc/d"]

    assert rsync_replay.build_filter(keep, dropins) == "## keep\n/a\n\n/b\nx/etc/c\n/d"


def test_build_filter_without_dropins_is_the_stripped_keep_list():
    assert rsync_replay.build_filter("/etc/a\n", []) == "/a\n"


def test_parse_itemized_keeps_files_and_symlinks_only():
    stdout = (
        "cd+++++++++ systemd/\n"
        ">f+++++++++ udev/rules.d/90-steamos-mounter.rules\n"
        "cL+++++++++ systemd/x.device.wants/y.service\n"
        "cS+++++++++ sock\n"
        "\n"
    )

    assert rsync_replay.parse_itemized(stdout) == {
        "/etc/udev/rules.d/90-steamos-mounter.rules",
        "/etc/systemd/x.device.wants/y.service",
    }


def test_parse_itemized_decodes_rsync_octal_escapes():
    assert rsync_replay.parse_itemized(">f+++++++++ a\\#040b\n") == {"/etc/a b"}


def test_parse_itemized_rejects_a_line_without_an_11_character_itemize():
    with pytest.raises(ValueError, match="itemize"):
        rsync_replay.parse_itemized(">f+++++ short/name\n")


@pytest.mark.parametrize("path", ["/usr/lib/x", "etc/x", "/etc/café"])
def test_replay_rejects_paths_it_cannot_check(path):
    with pytest.raises(ValueError, match="expected path"):
        rsync_replay.replay("", [], {path: None})


@pytest.mark.rsync
def test_replay_two_glob_example_covers_matching_files_and_links():
    keep_list = "## default keep-list\n/etc/foo/**\n"
    dropins = ["## a drop-in\n/etc/bar.conf\n"]
    expected = {
        "/etc/foo/a.conf": None,
        "/etc/foo/sub/b": None,
        "/etc/foo/link": "/etc/bar.conf",
        "/etc/bar.conf": None,
        "/etc/baz.conf": None,
    }

    covered = rsync_replay.replay(keep_list, dropins, expected)

    assert covered == {
        "/etc/foo/a.conf",
        "/etc/foo/sub/b",
        "/etc/foo/link",
        "/etc/bar.conf",
    }


@pytest.mark.rsync
def test_replay_positive_control_deck_keep_list_and_our_dropin_cover_all():
    keep_list = load_fixture("atomic-update-keep.conf").decode("utf-8")

    covered = rsync_replay.replay(
        keep_list, [all_conf_dropin(), OUR_DROPIN], INSTALLED_ETC
    )

    assert covered == set(INSTALLED_ETC)


@pytest.mark.rsync
def test_replay_negative_control_without_our_dropin_misses_registry_and_rule():
    keep_list = load_fixture("atomic-update-keep.conf").decode("utf-8")

    covered = rsync_replay.replay(keep_list, [all_conf_dropin()], INSTALLED_ETC)

    assert set(INSTALLED_ETC) - covered == {
        "/etc/steamos-mounter/config.toml",
        "/etc/udev/rules.d/90-steamos-mounter.rules",
    }


@pytest.mark.rsync
def test_replay_raises_when_rsync_fails(monkeypatch):
    monkeypatch.setattr(rsync_replay, "RSYNC", "/usr/bin/false")

    with pytest.raises(RuntimeError, match="rsync exited 1"):
        rsync_replay.replay("/etc/a\n", [], {"/etc/a": None})


@pytest.mark.rsync
def test_replay_removes_its_scratch_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(rsync_replay.tempfile, "tempdir", str(tmp_path))

    rsync_replay.replay("/etc/a\n", [], {"/etc/a": None})

    assert list(tmp_path.iterdir()) == []
