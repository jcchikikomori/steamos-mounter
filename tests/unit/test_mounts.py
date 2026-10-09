"""findmnt parsing, read-back by mountpoint, the mount table and the held check.

Design Doc "blockdev, mounts, naming, escape", Fact Disposition Table row
"deck:/usr/bin/findmnt:state-readback" and Headline Finding 3. Each trap is
pinned on the real Deck capture that shows it:

- ``findmnt-sdb5-not-mounted.json``, ``findmnt-dm-0-not-mounted.json``: exit 1
  with no output means "not mounted", never a tool failure;
- ``findmnt-*-adr-columns.json``: VFS and FS options as two lists, and no
  ``maj:min`` column at all;
- ``findmnt-real-list.json``: bind sources ending in ``[/subpath]`` and the
  btrfs root on the anonymous device number ``0:28``; it holds neither
  ``/dev/sdb5`` nor ``/dev/dm-0`` (the "not mounted" baseline).

The synthetic read-backs stand in for V-11 captures and are loaded by name
only, so swapping them for real ones needs no test edits. The locale evidence
proves the ``LC_ALL=C`` captures equal ``C.UTF-8`` output for ASCII text.
"""

import dataclasses
import json

import pytest

from steamos_mounter.blockdev import BlockDevice, DeviceTree, parse_lsblk_json
from steamos_mounter.errors import ExitCode, ToolError
from steamos_mounter.model import MountInfo
from steamos_mounter.mounts import (
    FINDMNT_COLUMNS,
    at_target,
    canonical_source,
    for_device,
    parse_findmnt,
    table,
)
from steamos_mounter.runner import CommandResult
from tests.helpers.builders import lsblk_device
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import fixture_rc, load_fixture

FINDMNT = "/usr/bin/findmnt"
DESIGN_COLUMNS = "TARGET,SOURCE,FSTYPE,VFS-OPTIONS,FS-OPTIONS,MAJ:MIN"
REAL_LIST = "findmnt-real-list.json"
NOT_MOUNTED = ("findmnt-sdb5-not-mounted.json", "findmnt-dm-0-not-mounted.json")
MEDIABOX = "/run/media/deck/MEDIABOX"
TABLE_ARGV = (FINDMNT, "--json", "-o", DESIGN_COLUMNS, "--list", "--real")
NTFS_FUSE_OPTIONS = ("rw", "user_id=0", "group_id=0", "allow_other", "blksize=4096")
REMOVABLE_VFS_OPTIONS = ("rw", "nosuid", "nodev", "relatime")
NTFS3_OPTIONS = (
    "rw",
    "uid=1000",
    "gid=1000",
    "dmask=0022",
    "fmask=0022",
    "windows_names",
    "iocharset=utf8",
)
TOOL_MAPPING = "steamos-mounter-658207d5-5177-4a52-a297-31643c64724d"
UDISKS_DM0_NAME = "PAT4T4SHUAWEI_PERSONAL_4_3_2024"
UDISKS_DM1_NAME = "OBAMA_BACKUP_1_2_2025"
HOME_TARGETS = (
    "/home",
    "/srv",
    "/root",
    "/opt",
    "/nix",
    "/var/cache/pacman",
    "/var/lib/docker",
    "/var/lib/flatpak",
    "/var/lib/steamos-log-submitter",
    "/var/log",
    "/var/lib/systemd/coredump",
    "/var/tmp",
)


def mountpoint_argv(target: str) -> tuple[str, ...]:
    return (FINDMNT, "--json", "-o", DESIGN_COLUMNS, "--mountpoint", target)


def result(
    stdout: bytes = b"",
    *,
    returncode: int | None = 0,
    stderr: bytes = b"",
    timed_out: bool = False,
    not_found: bool = False,
) -> CommandResult:
    return CommandResult(
        argv=(FINDMNT,),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        secret=None,
        timed_out=timed_out,
        not_found=not_found,
        overflow=False,
    )


def capture(name: str) -> CommandResult:
    """A fixture as findmnt's result; synthetics (no index row) exited 0."""
    try:
        returncode = fixture_rc(name)
    except KeyError:
        returncode = 0
    return result(load_fixture(name), returncode=returncode)


def document(*filesystems: dict[str, object]) -> bytes:
    return json.dumps({"filesystems": list(filesystems)}).encode("utf-8")


def tree(name: str) -> DeviceTree:
    return parse_lsblk_json(load_fixture(name))


def real_device(kname: str) -> BlockDevice:
    return tree("lsblk-columns-tree.json").devices[kname]


def built_device(kname: str, devnum: str, path: str | None = None) -> BlockDevice:
    columns = {"maj:min": devnum} | ({"path": path} if path else {})
    return parse_lsblk_json(
        json.dumps({"blockdevices": [lsblk_device(kname, columns)]}).encode()
    ).devices[kname]


def targets(infos: tuple[MountInfo, ...]) -> tuple[str, ...]:
    return tuple(info.target for info in infos)


# --- constants ---------------------------------------------------------------


def test_findmnt_columns_match_the_design_doc():
    assert FINDMNT_COLUMNS == DESIGN_COLUMNS


# --- "not mounted" -----------------------------------------------------------


@pytest.mark.parametrize("name", NOT_MOUNTED)
def test_not_mounted_is_empty_not_error(name):
    found = capture(name)

    assert (found.returncode, found.stdout) == (1, b"")
    assert parse_findmnt(found) == ()


@pytest.mark.parametrize("name", NOT_MOUNTED)
def test_at_target_not_mounted_is_none(ctx, fake_runner, name):
    fake_runner.on(FINDMNT, name)

    assert at_target(ctx, MEDIABOX) is None
    assert fake_runner.argvs == [mountpoint_argv(MEDIABOX)]


@pytest.mark.parametrize(
    "failed",
    [
        result(returncode=2, stderr=b"findmnt: bad usage"),
        result(b"{}", returncode=1),
        result(returncode=None, timed_out=True),
        result(returncode=None, not_found=True),
        result(returncode=0),
    ],
    ids=["exit-2", "exit-1-with-output", "timeout", "not-found", "exit-0-empty"],
)
def test_other_outcomes_are_tool_errors(failed):
    with pytest.raises(ToolError) as caught:
        parse_findmnt(failed)

    assert caught.value.exit_code == ExitCode.FAILED
    assert caught.value.user_message == "cannot read the mount table"


@pytest.mark.parametrize(
    "stdout",
    [
        b"not json",
        b"[]",
        b'{"mounts": []}',
        b'{"filesystems": {}}',
        b'{"filesystems": ["/"]}',
        document({"source": "/dev/sda1", "fstype": "ext4"}),
        document({"target": "/", "source": None, "fstype": "ext4"}),
        document({"target": "/", "source": "/dev/x", "fstype": "ext4", "maj:min": 8}),
        document(
            {"target": "/", "source": "/dev/x", "fstype": "ext4", "vfs-options": 1}
        ),
        document({"target": "/", "source": "/dev/x", "fstype": "ext4", "children": {}}),
    ],
    ids=[
        "not-json",
        "not-object",
        "no-filesystems",
        "not-list",
        "not-node",
        "no-target",
        "null-source",
        "number-devnum",
        "number-options",
        "children-not-list",
    ],
)
def test_malformed_output_is_a_tool_error(stdout):
    with pytest.raises(ToolError):
        parse_findmnt(result(stdout))


# --- options and read_only (adr-columns captures) -----------------------------


def test_adr_columns_capture_splits_both_option_lists():
    (info,) = parse_findmnt(capture("findmnt-sda1-adr-columns.json"))

    assert info == MountInfo(
        target="/run/media/deck/EXT256",
        source="/dev/sda1",
        fstype="ext4",
        vfs_options=("rw", "nosuid", "nodev", "noatime"),
        fs_options=("rw", "errors=remount-ro", "stripe=8191"),
        devnum=None,
    )


def test_adr_columns_capture_of_the_sd_card():
    (info,) = parse_findmnt(capture("findmnt-mmcblk0p1-adr-columns.json"))

    assert info.vfs_options == ("rw", "nosuid", "nodev", "noatime")
    assert info.fs_options == ("rw", "errors=remount-ro")
    assert info.devnum is None


@pytest.mark.parametrize(
    "name", ["findmnt-sda1-adr-columns.json", "findmnt-mmcblk0p1-adr-columns.json"]
)
def test_errors_remount_ro_is_not_read_only(name):
    (info,) = parse_findmnt(capture(name))

    assert info.read_only is False


def test_ro_in_either_list_is_read_only():
    (info,) = parse_findmnt(capture("findmnt-fuseblk-ro.json"))

    assert info.read_only is True


def test_empty_and_null_options_are_empty_tuples():
    (info,) = parse_findmnt(
        result(
            document(
                {
                    "target": "/x",
                    "source": "none",
                    "fstype": "tmpfs",
                    "vfs-options": "",
                    "fs-options": None,
                    "maj:min": None,
                }
            )
        )
    )

    assert (info.vfs_options, info.fs_options, info.devnum) == ((), (), None)


def test_nested_children_are_flattened_in_order():
    child = {"target": "/b", "source": "/dev/sdc1", "fstype": "exfat"}
    parent = {"target": "/a", "source": "/dev/sdb5", "fstype": "ntfs3"}
    sibling = {"target": "/c", "source": "/dev/sdd1", "fstype": "vfat"}

    found = parse_findmnt(result(document(parent | {"children": [child]}, sibling)))

    assert targets(found) == ("/a", "/b", "/c")


def test_undecodable_bytes_survive_as_surrogates():
    target = "/run/media/deck/MÉDIA"
    raw = document({"target": target, "source": "/dev/x", "fstype": "ext4"})
    raw = raw.replace(b"\\u00c9", b"\xff")

    (info,) = parse_findmnt(result(raw))

    assert info.target == "/run/media/deck/M\udcffDIA"


# --- the real list -----------------------------------------------------------


def test_real_list_has_every_row():
    found = parse_findmnt(capture(REAL_LIST))

    assert len(found) == 21
    assert found[0].target == "/"


def test_btrfs_root_has_the_anonymous_device_number():
    root = parse_findmnt(capture(REAL_LIST))[0]

    assert (root.source, root.fstype, root.devnum) == (
        "/dev/nvme0n1p4",
        "btrfs",
        "0:28",
    )


def test_bind_source_keeps_its_subpath_in_the_row():
    by_target = {info.target: info for info in parse_findmnt(capture(REAL_LIST))}

    assert by_target["/srv"].source == "/dev/nvme0n1p8[/.steamos/offload/srv]"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("/dev/nvme0n1p8[/.steamos/offload/srv]", "/dev/nvme0n1p8"),
        ("/dev/nvme0n1p8[/.steamos/offload/var/lib/docker]", "/dev/nvme0n1p8"),
        ("/dev/sda1[/]", "/dev/sda1"),
        ("/dev/sdb5", "/dev/sdb5"),
        ("owlcord.appimage", "owlcord.appimage"),
        ("/dev/mapper/A[B]", "/dev/mapper/A[B]"),
        ("/dev/mapper/A[/x", "/dev/mapper/A[/x"),
    ],
)
def test_canonical_source_strips_only_a_bind_subpath(source, expected):
    assert canonical_source(source) == expected


def test_real_list_is_the_not_mounted_baseline():
    rows = parse_findmnt(capture(REAL_LIST))

    assert for_device(rows, real_device("sdb5"), None) == ()
    assert for_device(rows, real_device("dm-0"), UDISKS_DM0_NAME) == ()
    assert for_device(rows, real_device("sdb1"), None) == ()


# --- for_device (held check) -------------------------------------------------


def test_for_device_finds_binds_through_the_stripped_source():
    rows = parse_findmnt(capture(REAL_LIST))
    stripped = tuple(dataclasses.replace(info, devnum=None) for info in rows)

    assert targets(for_device(stripped, real_device("nvme0n1p8"), None)) == HOME_TARGETS


def test_for_device_finds_btrfs_by_source_despite_the_anonymous_number():
    rows = parse_findmnt(capture(REAL_LIST))

    assert targets(for_device(rows, real_device("nvme0n1p4"), None)) == ("/",)


def test_for_device_matches_by_device_number():
    info = MountInfo(
        target="/run/media/deck/MEDIABOX",
        source="/dev/disk/by-uuid/01D95F1575592A30",
        fstype="ntfs3",
        vfs_options=(),
        fs_options=(),
        devnum="8:21",
    )

    assert for_device((info,), real_device("sdb5"), None) == (info,)


def test_for_device_matches_the_kname_path_when_lsblk_shows_a_mapper_path():
    info = MountInfo(
        target="/run/media/deck/PERSONAL",
        source="/dev/dm-0",
        fstype="ntfs3",
        vfs_options=(),
        fs_options=(),
        devnum=None,
    )

    assert for_device((info,), real_device("dm-0"), None) == (info,)


def test_for_device_matches_dev_mapper_name_only_through_dm():
    (info,) = parse_findmnt(capture("findmnt-obama-ntfs3-rw.json"))
    info = dataclasses.replace(info, devnum=None)
    dm1 = built_device("dm-1", "252:1")

    assert for_device((info,), dm1, None) == ()
    assert for_device((info,), dm1, UDISKS_DM1_NAME) == (info,)


def test_for_device_never_matches_a_longer_device_name():
    info = MountInfo(
        target="/x",
        source="/dev/sda10",
        fstype="ext4",
        vfs_options=(),
        fs_options=(),
        devnum="8:10",
    )

    assert for_device((info,), real_device("sda1"), None) == ()


def test_for_device_finds_the_udisks_mount_of_dm0():
    rows = parse_findmnt(capture("findmnt-list-dm0-at-udisks-path.json"))

    found = for_device(rows, real_device("dm-0"), UDISKS_DM0_NAME)

    assert targets(found) == ("/run/media/deck/PERSONAL1",)


def test_for_device_finds_the_udisks_mount_of_dm1():
    dolphin = tree("lsblk-tree-dolphin-unregistered.json")
    rows = parse_findmnt(capture("findmnt-list-dm1-at-udisks-path.json"))

    found = for_device(rows, dolphin.devices["dm-1"], UDISKS_DM1_NAME)

    assert targets(found) == ("/run/media/deck/OBAMA",)


def test_for_device_finds_mediabox_in_the_mounted_list():
    rows = parse_findmnt(capture("findmnt-list-with-mediabox.json"))

    assert targets(for_device(rows, real_device("sdb5"), None)) == (MEDIABOX,)


@pytest.mark.parametrize(
    "name",
    [
        "findmnt-list-with-mediabox.json",
        "findmnt-list-dm1-at-udisks-path.json",
        "findmnt-list-dm0-at-udisks-path.json",
    ],
)
def test_synthetic_list_is_the_real_list_plus_one_row(name):
    real = parse_findmnt(capture(REAL_LIST))

    synthetic = parse_findmnt(capture(name))

    assert synthetic[: len(real)] == real
    assert len(synthetic) == len(real) + 1


# --- at_target and table -----------------------------------------------------


def test_at_target_reads_back_the_mount(ctx, fake_runner):
    fake_runner.on(
        FINDMNT, Answer.from_fixture("findmnt-mediabox-fuseblk-rw.json", returncode=0)
    )

    info = at_target(ctx, MEDIABOX)

    assert fake_runner.argvs == [mountpoint_argv(MEDIABOX)]
    assert info == MountInfo(
        target=MEDIABOX,
        source="/dev/sdb5",
        fstype="fuseblk",
        vfs_options=REMOVABLE_VFS_OPTIONS,
        fs_options=NTFS_FUSE_OPTIONS,
        devnum="0:92",
    )
    assert for_device((info,), real_device("sdb5"), None) == (info,)


def test_at_target_returns_the_topmost_of_stacked_mounts(ctx, fake_runner):
    lower = {"target": MEDIABOX, "source": "/dev/sdb5", "fstype": "ntfs3"}
    upper = {"target": MEDIABOX, "source": "/dev/sdc1", "fstype": "exfat"}
    fake_runner.on(FINDMNT, Answer(stdout=document(lower, upper)))

    assert at_target(ctx, MEDIABOX).source == "/dev/sdc1"


def test_at_target_refuses_a_relative_target(ctx, fake_runner):
    with pytest.raises(ValueError, match="absolute"):
        at_target(ctx, "run/media/deck/MEDIABOX")

    assert fake_runner.calls == []


def test_at_target_tool_failure_is_a_tool_error(ctx, fake_runner):
    fake_runner.on(FINDMNT, Answer.timeout())

    with pytest.raises(ToolError):
        at_target(ctx, MEDIABOX)


def test_table_reads_the_real_list(ctx, fake_runner):
    fake_runner.on(FINDMNT, REAL_LIST)

    rows = table(ctx)

    assert fake_runner.argvs == [TABLE_ARGV]
    assert len(rows) == 21


def test_table_with_no_rows_is_empty(ctx, fake_runner):
    fake_runner.on(FINDMNT, Answer(returncode=1))

    assert table(ctx) == ()


def test_table_unexpected_exit_is_a_tool_error(ctx, fake_runner):
    fake_runner.on(FINDMNT, Answer(returncode=2))

    with pytest.raises(ToolError):
        table(ctx)


# --- synthetic read-backs ----------------------------------------------------

READ_BACKS = {
    "findmnt-mediabox-fuseblk-rw.json": (MEDIABOX, "/dev/sdb5", "fuseblk", False),
    "findmnt-movies-fuseblk-rw.json": (
        "/run/media/deck/MOVIES",
        "/dev/sdc1",
        "fuseblk",
        False,
    ),
    "findmnt-games-exfat-rw.json": (
        "/run/media/deck/GAMES",
        "/dev/sdc1",
        "exfat",
        False,
    ),
    "findmnt-obama-ntfs3-rw.json": (
        "/run/media/deck/OBAMA",
        f"/dev/mapper/{UDISKS_DM1_NAME}",
        "ntfs3",
        False,
    ),
    "findmnt-personal-ntfs3-rw.json": (
        "/run/media/deck/PERSONAL",
        f"/dev/mapper/{TOOL_MAPPING}",
        "ntfs3",
        False,
    ),
    "findmnt-fuseblk-ro.json": (MEDIABOX, "/dev/sdb5", "fuseblk", True),
    "findmnt-ntfs-rw.json": (MEDIABOX, "/dev/sdb5", "ntfs", False),
    "findmnt-vfat-rw.json": ("/run/media/deck/STICK", "/dev/sdc1", "vfat", False),
    "findmnt-btrfs-rw.json": ("/run/media/deck/DATA", "/dev/sdc1", "btrfs", False),
}


@pytest.mark.parametrize("name", sorted(READ_BACKS))
def test_synthetic_read_back(name):
    (info,) = parse_findmnt(capture(name))

    assert (info.target, info.source, info.fstype, info.read_only) == READ_BACKS[name]
    assert info.vfs_options[1:3] == ("nosuid", "nodev")
    assert "noexec" not in info.vfs_options


def test_games_read_back_has_the_exfat_options():
    (info,) = parse_findmnt(capture("findmnt-games-exfat-rw.json"))

    assert info.devnum == "8:33"
    assert "iocharset=utf8" in info.fs_options


def test_ntfs3_read_backs_carry_the_mapping_numbers():
    (personal,) = parse_findmnt(capture("findmnt-personal-ntfs3-rw.json"))
    (obama,) = parse_findmnt(capture("findmnt-obama-ntfs3-rw.json"))

    assert (personal.devnum, obama.devnum) == ("252:0", "252:1")
    assert personal.fs_options == NTFS3_OPTIONS


def test_btrfs_read_back_matches_only_by_source():
    (info,) = parse_findmnt(capture("findmnt-btrfs-rw.json"))
    sdc1 = built_device("sdc1", "8:33")

    assert info.devnum != sdc1.devnum
    assert for_device((info,), sdc1, None) == (info,)


# --- locale evidence (DD-01) -------------------------------------------------


def evidence_lines(tool: str) -> list[str]:
    name = f"evidence/evidence-locale-diff-{tool}.txt"
    return load_fixture(name).decode("utf-8").splitlines()


@pytest.mark.parametrize("tool", ["lsblk", "findmnt"])
def test_ascii_output_is_the_same_under_c_and_c_utf8(tool):
    assert evidence_lines(tool) == ["diff rc=0"]


def test_every_lsblk_and_findmnt_capture_is_ascii():
    # The evidence above covers ASCII text only; these captures are all ASCII,
    # so parsing them is what C.UTF-8 output would give.
    names = [
        "lsblk-columns-tree.json",
        "lsblk-columns-list.json",
        "lsblk-full-bytes.json",
        REAL_LIST,
        "findmnt-sda1-adr-columns.json",
        "findmnt-mmcblk0p1-adr-columns.json",
    ]

    assert [name for name in names if not load_fixture(name).isascii()] == []


def udev_diff_side(marker: str) -> dict[str, str]:
    lines = evidence_lines("udev-sdb1")
    rows = (line[2:] for line in lines if line.startswith(f"{marker} "))
    return dict(row.split("=", 1) for row in rows)


def as_set(name: str, value: str) -> frozenset[str]:
    return frozenset(value.split(" ") if name == "DEVLINKS" else value.split(":"))


def test_udev_diff_touches_only_unordered_properties():
    assert set(udev_diff_side("<")) == {"DEVLINKS", "TAGS", "CURRENT_TAGS"}
    assert set(udev_diff_side(">")) == {"DEVLINKS", "TAGS", "CURRENT_TAGS"}


@pytest.mark.parametrize("name", ["DEVLINKS", "TAGS", "CURRENT_TAGS"])
def test_devlinks_and_tags_compare_as_sets(name):
    c_locale = udev_diff_side("<")[name]
    c_utf8 = udev_diff_side(">")[name]

    assert c_locale != c_utf8
    assert as_set(name, c_locale) == as_set(name, c_utf8)
