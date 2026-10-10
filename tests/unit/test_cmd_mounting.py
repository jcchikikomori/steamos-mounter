"""``mount`` and ``unmount``: presence, eligibility, the marker, the final line.

Design Doc "CLI Contract > Commands" (``mount``, ``unmount``), "Required
Specific Tests" (``mount --device`` on an ineligible device, D013), D014,
DD-11, DD-26 and "Locks"; PRD AC-009, AC-062, AC-075.

The instance's reconcile pass runs inside systemd, so a test plays it with a
hook on the scripted ``systemctl start``/``reload``: the hook writes the
record reconcile would write, and the CLI then reads the view. Records,
locks and the leaf directories are real files under ``tmp_path``.
"""

import fcntl
import json
import os
import re

import pytest

from steamos_mounter.errors import ExitCode
from steamos_mounter.platforms.steamos import TOOLS
from tests.helpers.builders import record_dict
from tests.helpers.cli_env import (
    DETAILS,
    MEDIABOX_PATH,
    MEDIABOX_RECORD,
    MEDIABOX_REGISTRY,
    MEDIABOX_UNIT,
    PERSONAL_KEY_UNIT,
    PERSONAL_PATH,
    PERSONAL_RECORD,
    PERSONAL_REGISTRY,
    PERSONAL_UNIT,
    PERSONAL_UUID,
    findmnt_rows,
    given_host,
    partition,
    run_cli,
    script_table,
    script_tree,
    script_unit,
    show_argv,
    systemctl_calls,
    tree_with,
    verb_argv,
)
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture
from tests.helpers.flows import (
    CRYPTSETUP,
    make_leaf,
    read_record,
    readback_argv,
    write_record,
)

SDB5_AUTO_UNIT = "steamos-mounter-auto@sys-devices-host\\x2dtree-block-sdb-sdb5.service"
SDB5_AUTO_RECORD = "run/steamos-mounter/records/auto/sdb5-8_21.json"
MEDIABOX_LOCK = "run/steamos-mounter/locks/volume-01d95f1575592a30.lock"
PERSONAL_MAPPING = f"steamos-mounter-{PERSONAL_UUID}"
DM0_NAME = "sys/block/dm-0/dm/name"
STAMP = "2026-10-08T02:11:40Z"  # the FakeClock's start
WITH_MEDIABOX = Answer.from_fixture("findmnt-list-with-mediabox.json", returncode=0)
UMOUNT = TOOLS.umount


def mediabox_record(**changes):
    return record_dict(
        key="01d95f1575592a30",
        name="MEDIABOX",
        unit=MEDIABOX_UNIT,
        mapping=None,
        warning=None,
        next_step=None,
        **changes,
    )


def write_json(root, relative: str, data) -> None:
    write_record(root, relative, json.dumps(data).encode())


@pytest.fixture
def mediabox(ctx, tmp_path, fake_runner, host_tree):
    """MEDIABOX registered and plugged in (sdb5), the Deck's other devices too."""
    given_host(ctx, tmp_path, registry=MEDIABOX_REGISTRY)
    host_tree.add_sysfs_facts()
    script_tree(fake_runner)
    return tmp_path


def mounted_by_reconcile(root, relative: str, record: dict):
    """A hook that plays the instance's reconcile pass: it writes ``record``."""

    def hook(_command) -> None:
        write_json(root, relative, record)

    return hook


MEDIABOX_MOUNTED = mediabox_record(
    state="MountedRWDirty",
    reason="dirty",
    mount={
        "status": "mounted",
        "target": MEDIABOX_PATH,
        "device": "/dev/sdb5",
        "devnum": "8:21",
        "driver": "ntfs-3g",
        "mode": "rw",
        "created_dir": True,
    },
)


# --- mount: presence and the final line (AC-009) --------------------------------------


def test_mount_present(ctx, mediabox, fake_runner):
    script_unit(fake_runner, MEDIABOX_UNIT, "inactive")
    fake_runner.on(
        verb_argv("start", MEDIABOX_UNIT, block=True),
        Answer(),
        hook=mounted_by_reconcile(mediabox, MEDIABOX_RECORD, MEDIABOX_MOUNTED),
    )
    script_table(fake_runner, WITH_MEDIABOX)

    result = run_cli(ctx, "mount", "--volume", "mediabox")

    assert (result.code, result.err) == (ExitCode.OK, "")
    assert result.out == (
        f"MEDIABOX: mounted read-write via ntfs-3g (dirty) at {MEDIABOX_PATH}\n"
    )
    assert systemctl_calls(fake_runner) == [
        show_argv(MEDIABOX_UNIT),
        verb_argv("start", MEDIABOX_UNIT, block=True),
    ]
    start = next(call for call in fake_runner.calls if call.argv[1] == "start")
    assert start.timeout == 120.0


def test_mount_absent_exit_7(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path, registry=MEDIABOX_REGISTRY)
    script_tree(fake_runner, tree_with(partition("sdc1", fstype="exfat")))

    result = run_cli(ctx, "mount", "--volume", "MEDIABOX")

    assert result.code == ExitCode.NOT_PRESENT
    assert result.err == f"steamos-mounter: MEDIABOX is not plugged in. {DETAILS}\n"
    assert systemctl_calls(fake_runner) == []


def test_mount_of_an_unknown_name_exits_2(ctx, mediabox, fake_runner):
    result = run_cli(ctx, "mount", "--volume", "GAMES")

    assert result.code == ExitCode.USAGE
    assert systemctl_calls(fake_runner) == []


def test_mount_that_does_not_mount_exits_1_with_the_next_step(
    ctx, mediabox, fake_runner
):
    failed = mediabox_record(state="MountFailed", reason="unknown", mount=None)
    script_unit(fake_runner, MEDIABOX_UNIT, "failed")
    fake_runner.on(
        verb_argv("start", MEDIABOX_UNIT, block=True),
        Answer(returncode=1),
        hook=mounted_by_reconcile(mediabox, MEDIABOX_RECORD, failed),
    )
    script_table(fake_runner)

    result = run_cli(ctx, "mount", "--volume", "MEDIABOX")

    assert result.code == ExitCode.FAILED
    assert result.out == (
        "MEDIABOX: mount failed. See the journal, then run sudo"
        " /opt/steamos-mounter/bin/steamos-mounter mount --volume MEDIABOX.\n"
    )


# --- mount: the marker under the lock, then systemctl (D014) -------------------------


def test_marker_written_under_the_lock_and_released_before_systemctl(
    ctx, mediabox, fake_runner
):
    write_json(mediabox, MEDIABOX_RECORD, MEDIABOX_MOUNTED)
    seen = {}

    def at_reload(_command) -> None:
        seen["record"] = read_record(mediabox, MEDIABOX_RECORD)
        fd = os.open(mediabox / MEDIABOX_LOCK, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # raises if still held
            seen["lock_free"] = True
        finally:
            os.close(fd)

    script_unit(fake_runner, MEDIABOX_UNIT, "active")
    fake_runner.on(
        verb_argv("reload", MEDIABOX_UNIT, block=True), Answer(), hook=at_reload
    )
    script_table(fake_runner, WITH_MEDIABOX)

    result = run_cli(ctx, "mount", "--volume", "MEDIABOX")

    assert result.code == ExitCode.OK
    marker = seen["record"]["cli_request"]
    assert re.fullmatch(r"[0-9a-f]{16}", marker["token"])
    assert marker["at"] == STAMP
    assert seen["lock_free"] is True
    assert verb_argv("start", MEDIABOX_UNIT, block=True) not in fake_runner.argvs


def test_a_first_mount_writes_a_named_record_with_the_marker(
    ctx, mediabox, fake_runner
):
    seen = {}
    script_unit(fake_runner, MEDIABOX_UNIT, "activating")
    fake_runner.on(
        verb_argv("reload", MEDIABOX_UNIT, block=True),
        Answer(),
        hook=lambda _cmd: seen.update(read_record(mediabox, MEDIABOX_RECORD)),
    )
    script_table(fake_runner)

    run_cli(ctx, "mount", "--volume", "MEDIABOX")

    assert (seen["name"], seen["unit"]) == ("MEDIABOX", MEDIABOX_UNIT)
    assert seen["cli_request"]["at"] == STAMP


def test_an_unreadable_record_gets_no_marker(ctx, mediabox, fake_runner):
    write_record(mediabox, MEDIABOX_RECORD, b"not json")
    script_unit(fake_runner, MEDIABOX_UNIT, "active")
    fake_runner.on(verb_argv("reload", MEDIABOX_UNIT, block=True), Answer())
    script_table(fake_runner)

    run_cli(ctx, "mount", "--volume", "MEDIABOX")

    assert (mediabox / MEDIABOX_RECORD).read_bytes() == b"not json"


# --- mount: the key dialog (AC-075) ---------------------------------------------------


@pytest.fixture
def personal(ctx, tmp_path, fake_runner, host_tree):
    """PERSONAL registered, its container sdb1 plugged in and locked."""
    given_host(ctx, tmp_path, registry=PERSONAL_REGISTRY)
    host_tree.add_sysfs_facts()
    fake_runner.on(
        (TOOLS.lsblk,),
        Answer(stdout=load_fixture("lsblk-tree-personal-locked.json")),
        repeat=True,
    )
    return tmp_path


NEEDS_KEY = record_dict(
    state="NeedsKey",
    reason="stored_key_missing",
    warning=None,
    next_step=None,
    mount=None,
)


@pytest.mark.parametrize("dialog", ["key-unit-active", "record-says-open"])
def test_cli_mount_starts_key_unit(ctx, personal, fake_runner, dialog):
    record = NEEDS_KEY
    key_state = "active"
    if dialog == "record-says-open":
        record = record_dict(
            state="NeedsKey", reason="dialog_open", next_step=None, mount=None
        )
        key_state = "inactive"
    script_unit(fake_runner, PERSONAL_UNIT, "inactive")
    script_unit(fake_runner, PERSONAL_KEY_UNIT, key_state)
    fake_runner.on(
        verb_argv("start", PERSONAL_UNIT, block=True),
        Answer(),
        hook=mounted_by_reconcile(personal, PERSONAL_RECORD, record),
    )
    script_table(fake_runner)

    result = run_cli(ctx, "mount", "--volume", "PERSONAL")

    assert result.code == ExitCode.OK
    assert result.out == "PERSONAL: key dialog opened. Answer it on the Deck's screen\n"
    # The start trigger permits the dialog: no reload, the marker is redundant (D014).
    assert verb_argv("start", PERSONAL_UNIT, block=True) in fake_runner.argvs
    assert verb_argv("reload", PERSONAL_UNIT, block=True) not in fake_runner.argvs


def test_needs_key_without_a_dialog_exits_1(ctx, personal, fake_runner):
    script_unit(fake_runner, PERSONAL_UNIT, "inactive")
    script_unit(fake_runner, PERSONAL_KEY_UNIT, "inactive")
    fake_runner.on(
        verb_argv("start", PERSONAL_UNIT, block=True),
        Answer(),
        hook=mounted_by_reconcile(personal, PERSONAL_RECORD, NEEDS_KEY),
    )
    script_table(fake_runner)

    result = run_cli(ctx, "mount", "--volume", "PERSONAL")

    assert result.code == ExitCode.FAILED
    assert result.out.startswith("PERSONAL: needs a key. In Desktop Mode")


def test_mount_of_a_mapping_targets_its_registered_container(
    ctx, tmp_path, fake_runner, host_tree
):
    given_host(ctx, tmp_path, registry=PERSONAL_REGISTRY)
    host_tree.add_sysfs_facts()
    script_tree(fake_runner)  # the Deck capture: dm-0 open on sdb1
    script_unit(fake_runner, PERSONAL_UNIT, "active")
    fake_runner.on(verb_argv("reload", PERSONAL_UNIT, block=True), Answer())
    script_unit(fake_runner, PERSONAL_KEY_UNIT, "inactive")
    script_table(fake_runner)

    run_cli(ctx, "mount", "--device", "/dev/dm-0")

    assert verb_argv("reload", PERSONAL_UNIT, block=True) in fake_runner.argvs


# --- mount --device: the auto instance and D013 ---------------------------------------


def test_mount_device_of_an_unregistered_volume_starts_its_auto_instance(
    ctx, tmp_path, fake_runner, host_tree
):
    given_host(ctx, tmp_path)
    host_tree.add_sysfs_facts()
    script_tree(fake_runner)
    auto = record_dict(
        kind="auto",
        key="sdb5-8_21",
        name="MEDIABOX",
        unit=SDB5_AUTO_UNIT,
        state="MountedRW",
        reason=None,
        mapping=None,
        mount=dict(MEDIABOX_MOUNTED["mount"], driver="ntfs3"),
        source={"kname": "sdb5", "devnum": "8:21", "syspath": None},
    )
    script_unit(fake_runner, SDB5_AUTO_UNIT, "inactive")
    fake_runner.on(
        verb_argv("start", SDB5_AUTO_UNIT, block=True),
        Answer(),
        hook=mounted_by_reconcile(tmp_path, SDB5_AUTO_RECORD, auto),
    )
    script_table(fake_runner, WITH_MEDIABOX)

    result = run_cli(ctx, "mount", "--device", "/dev/sdb5")

    assert result.code == ExitCode.OK, result.err
    assert result.out.startswith(f"MEDIABOX: mounted read-write at {MEDIABOX_PATH}")
    # No auto record existed, so there was no marker to write.
    assert systemctl_calls(fake_runner)[0] == show_argv(SDB5_AUTO_UNIT)


def test_an_auto_instance_that_takes_nothing_exits_1(
    ctx, tmp_path, fake_runner, host_tree
):
    given_host(ctx, tmp_path)
    host_tree.add_sysfs_facts()
    script_tree(fake_runner)
    script_unit(fake_runner, SDB5_AUTO_UNIT, "inactive")
    fake_runner.on(verb_argv("start", SDB5_AUTO_UNIT, block=True), Answer())
    script_table(fake_runner)

    result = run_cli(ctx, "mount", "--device", "/dev/sdb5")

    assert result.code == ExitCode.FAILED
    assert result.out == "MEDIABOX: not mounted: steamos-mounter does not handle it\n"


@pytest.mark.parametrize(
    ("device", "reason"),
    [
        ("/dev/sda1", "ext4 (SteamOS handles it)"),
        ("/dev/nvme0n1p8", "OS partition"),
        ("/dev/sdb2", "no filesystem"),
    ],
    ids=["ext4", "os-partition", "no-filesystem"],
)
def test_mount_device_refuses_ineligible_devices_before_systemctl(
    ctx, tmp_path, fake_runner, device, reason
):
    given_host(ctx, tmp_path)
    script_tree(fake_runner)

    result = run_cli(ctx, "mount", "--device", device)

    assert result.code == ExitCode.REFUSED
    assert result.err == (
        f"steamos-mounter: cannot mount {device}: {reason}. {DETAILS}\n"
    )
    assert systemctl_calls(fake_runner) == []


def test_mount_device_refuses_a_mapping_without_a_bitlocker_container(
    ctx, tmp_path, fake_runner
):
    given_host(ctx, tmp_path)
    luks = partition(
        "sdc1",
        fstype="crypto_LUKS",
        uuid="11111111-2222-3333-4444-555555555555",
        children=[
            partition("dm-1", type="crypt", fstype="ext4", pkname="sdc1", uuid="X")
        ],
    )
    script_tree(fake_runner, tree_with(luks))

    result = run_cli(ctx, "mount", "--device", "/dev/dm-1")

    assert result.code == ExitCode.REFUSED
    assert "unlocked mapping: register its container /dev/sdc1" in result.err
    assert systemctl_calls(fake_runner) == []


def test_mount_device_refuses_with_an_unknown_os_set(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path, os_set=False)
    script_tree(fake_runner)

    result = run_cli(ctx, "mount", "--device", "/dev/sdb5")

    assert result.code == ExitCode.REFUSED
    assert "OS partition list unreadable" in result.err
    assert systemctl_calls(fake_runner) == []


def test_a_registered_volume_mounts_by_device_even_with_an_unknown_os_set(
    ctx, tmp_path, fake_runner, host_tree
):
    given_host(ctx, tmp_path, registry=MEDIABOX_REGISTRY, os_set=False)
    host_tree.link_by_uuid("01D95F1575592A30", "sdb5")
    script_tree(fake_runner)
    script_unit(fake_runner, MEDIABOX_UNIT, "inactive")
    fake_runner.on(verb_argv("start", MEDIABOX_UNIT, block=True), Answer())
    script_table(fake_runner)

    run_cli(ctx, "mount", "--device", "/dev/disk/by-uuid/01D95F1575592A30")

    assert verb_argv("start", MEDIABOX_UNIT, block=True) in fake_runner.argvs


def test_mount_device_that_is_not_attached_exits_7(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path)
    script_tree(fake_runner)

    result = run_cli(ctx, "mount", "--device", "/dev/sdz1")

    assert result.code == ExitCode.NOT_PRESENT
    assert systemctl_calls(fake_runner) == []


# --- unmount (AC-062, DD-11, DD-26) ---------------------------------------------------


PERSONAL_MOUNTED = record_dict(
    state="MountedRW",
    reason=None,
    warning=None,
    mapping={
        "name": PERSONAL_MAPPING,
        "kname": "dm-0",
        "devnum": "252:0",
        "opened_by": "handler",
        "key_unit_invocation_id": None,
        "save_pending": False,
    },
    mount={
        "status": "mounted",
        "target": PERSONAL_PATH,
        "device": "/dev/dm-0",
        "devnum": "252:0",
        "driver": "ntfs3",
        "mode": "rw",
        "created_dir": True,
    },
)
MOUNTED_ROW = findmnt_rows((PERSONAL_PATH, "/dev/dm-0", "ntfs3", "252:0"))
NOT_MOUNTED = Answer(returncode=1)


@pytest.fixture
def personal_mounted(ctx, tmp_path, fake_runner, host_tree):
    """PERSONAL unlocked by the tool (dm-0) and mounted at its fixed path."""
    given_host(ctx, tmp_path, registry=PERSONAL_REGISTRY)
    host_tree.add_sysfs_facts()
    (tmp_path / DM0_NAME).write_text(f"{PERSONAL_MAPPING}\n", encoding="utf-8")
    make_leaf(tmp_path, PERSONAL_PATH)
    write_json(tmp_path, PERSONAL_RECORD, PERSONAL_MOUNTED)
    script_tree(fake_runner)
    return tmp_path


def test_unmount_closes_own_mapping(ctx, personal_mounted, fake_runner):
    fake_runner.on(readback_argv(PERSONAL_PATH), MOUNTED_ROW)
    fake_runner.on((UMOUNT, PERSONAL_PATH), Answer())
    fake_runner.on((CRYPTSETUP, "close", PERSONAL_MAPPING), Answer())

    result = run_cli(ctx, "unmount", "--volume", "PERSONAL")

    assert (result.code, result.err) == (ExitCode.OK, "")
    assert result.out == (
        f"unmounted PERSONAL from {PERSONAL_PATH}\nclosed {PERSONAL_MAPPING}\n"
    )
    record = read_record(personal_mounted, PERSONAL_RECORD)
    assert record["state"] == "UnmountedByUser"
    assert record["unmounted_by_user"] == {"devnum": "252:0", "at": STAMP}
    assert record["mount"]["status"] == "unmounted"
    assert record["mapping"] is None
    assert record["next_step"] == (
        "Run sudo /opt/steamos-mounter/bin/steamos-mounter mount --volume PERSONAL,"
        " or replug the drive."
    )
    assert not (personal_mounted / PERSONAL_PATH.lstrip("/")).exists()
    assert systemctl_calls(fake_runner) == []  # the instance stays active


def test_unmount_by_path_and_by_device_find_the_same_volume(
    ctx, personal_mounted, fake_runner
):
    fake_runner.on(readback_argv(PERSONAL_PATH), MOUNTED_ROW, NOT_MOUNTED)
    fake_runner.on((UMOUNT, PERSONAL_PATH), Answer())
    fake_runner.on((CRYPTSETUP, "close", PERSONAL_MAPPING), Answer())

    by_path = run_cli(ctx, "unmount", "--path", PERSONAL_PATH)
    by_device = run_cli(ctx, "unmount", "--device", "/dev/dm-0")

    assert by_path.code == ExitCode.OK
    assert by_device.code == ExitCode.OK
    assert by_device.out == "PERSONAL: not mounted by steamos-mounter\n"


def test_unmount_busy_exits_1_and_changes_nothing(ctx, personal_mounted, fake_runner):
    fake_runner.on(readback_argv(PERSONAL_PATH), MOUNTED_ROW)
    fake_runner.on(
        (UMOUNT, PERSONAL_PATH),
        Answer(
            returncode=32, stderr=f"umount: {PERSONAL_PATH}: target is busy.".encode()
        ),
    )

    result = run_cli(ctx, "unmount", "--volume", "PERSONAL")

    assert result.code == ExitCode.FAILED
    assert result.err == (
        f"steamos-mounter: {PERSONAL_PATH} is busy. Close the files open on"
        f" {PERSONAL_PATH} and try again. {DETAILS}\n"
    )
    assert read_record(personal_mounted, PERSONAL_RECORD) == PERSONAL_MOUNTED
    assert (UMOUNT, "-l", PERSONAL_PATH) not in fake_runner.argvs
    assert CRYPTSETUP not in [argv[0] for argv in fake_runner.argvs]


def test_unmount_failure_is_a_tool_error(ctx, personal_mounted, fake_runner):
    fake_runner.on(readback_argv(PERSONAL_PATH), MOUNTED_ROW)
    fake_runner.on((UMOUNT, PERSONAL_PATH), Answer(returncode=1, stderr=b"no"))

    result = run_cli(ctx, "unmount", "--volume", "PERSONAL")

    assert result.code == ExitCode.FAILED
    assert "PERSONAL could not be unmounted" in result.err


def test_a_mapping_that_does_not_close_is_recorded_then_reported(
    ctx, personal_mounted, fake_runner
):
    fake_runner.on(readback_argv(PERSONAL_PATH), MOUNTED_ROW)
    fake_runner.on((UMOUNT, PERSONAL_PATH), Answer())
    fake_runner.on((CRYPTSETUP, "close", PERSONAL_MAPPING), Answer(returncode=5))

    result = run_cli(ctx, "unmount", "--volume", "PERSONAL")

    assert result.code == ExitCode.FAILED
    assert "its unlocked mapping could not be closed" in result.err
    record = read_record(personal_mounted, PERSONAL_RECORD)
    assert record["state"] == "UnmountedByUser"
    assert record["mapping"]["name"] == PERSONAL_MAPPING


def test_unmount_leaves_a_foreign_mapping_alone(ctx, personal_mounted, fake_runner):
    foreign = dict(PERSONAL_MOUNTED, mapping=dict(PERSONAL_MOUNTED["mapping"]))
    foreign["mapping"]["name"] = "PAT4T4SHUAWEI_PERSONAL_4_3_2024"
    foreign["mount"] = dict(foreign["mount"], created_dir=False)
    write_json(personal_mounted, PERSONAL_RECORD, foreign)
    fake_runner.on(readback_argv(PERSONAL_PATH), MOUNTED_ROW)
    fake_runner.on((UMOUNT, PERSONAL_PATH), Answer())

    result = run_cli(ctx, "unmount", "--volume", "PERSONAL")

    assert result.code == ExitCode.OK
    assert result.out == f"unmounted PERSONAL from {PERSONAL_PATH}\n"
    assert (personal_mounted / PERSONAL_PATH.lstrip("/")).is_dir()  # not ours
    record = read_record(personal_mounted, PERSONAL_RECORD)
    assert record["mapping"]["name"] == "PAT4T4SHUAWEI_PERSONAL_4_3_2024"


def test_unmount_of_an_absent_volume_exits_7(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path, registry=MEDIABOX_REGISTRY)
    script_tree(fake_runner, tree_with(partition("sdc1", fstype="exfat")))

    result = run_cli(ctx, "unmount", "--volume", "MEDIABOX")

    assert result.code == ExitCode.NOT_PRESENT


def test_unmount_without_a_record_has_nothing_to_do(ctx, mediabox, fake_runner):
    result = run_cli(ctx, "unmount", "--volume", "MEDIABOX")

    assert (result.code, result.out) == (
        ExitCode.OK,
        "MEDIABOX: not mounted by steamos-mounter\n",
    )
    assert not (mediabox / MEDIABOX_RECORD).exists()


def test_unmount_with_an_unreadable_record_exits_1(ctx, mediabox, fake_runner):
    write_record(mediabox, MEDIABOX_RECORD, b"{")

    result = run_cli(ctx, "unmount", "--volume", "MEDIABOX")

    assert result.code == ExitCode.FAILED
    assert "the state record of MEDIABOX is unreadable" in result.err


def test_unmount_of_an_auto_volume_by_path(ctx, tmp_path, fake_runner, host_tree):
    given_host(ctx, tmp_path)
    host_tree.add_sysfs_facts()
    script_tree(fake_runner)
    target = "/run/media/deck/MEDIABOX"
    make_leaf(tmp_path, target)
    auto = record_dict(
        kind="auto",
        key="sdb5-8_21",
        name="MEDIABOX",
        unit=SDB5_AUTO_UNIT,
        state="MountedRW",
        mapping=None,
        mount=dict(MEDIABOX_MOUNTED["mount"], created_dir=True),
        source={"kname": "sdb5", "devnum": "8:21", "syspath": None},
    )
    write_json(tmp_path, SDB5_AUTO_RECORD, auto)
    fake_runner.on(
        readback_argv(target), findmnt_rows((target, "/dev/sdb5", "ntfs3", "8:21"))
    )
    fake_runner.on((UMOUNT, target), Answer())

    result = run_cli(ctx, "unmount", "--path", target)

    assert result.code == ExitCode.OK, result.err
    record = read_record(tmp_path, SDB5_AUTO_RECORD)
    assert record["unmounted_by_user"]["devnum"] == "8:21"
    assert record["next_step"] == (
        "Run sudo /opt/steamos-mounter/bin/steamos-mounter mount --device /dev/sdb5,"
        " or replug the drive."
    )


def test_unmount_of_an_auto_volume_that_is_gone_exits_7(
    ctx, tmp_path, fake_runner, host_tree
):
    given_host(ctx, tmp_path)
    script_tree(fake_runner, tree_with(partition("sdc1", fstype="exfat")))
    auto = record_dict(
        kind="auto",
        key="sdb5-8_21",
        name="MEDIABOX",
        mapping=None,
        mount=MEDIABOX_MOUNTED["mount"],
        source={"kname": "sdb5", "devnum": "8:21", "syspath": None},
    )
    write_json(tmp_path, SDB5_AUTO_RECORD, auto)

    result = run_cli(ctx, "unmount", "--path", MEDIABOX_PATH)

    assert result.code == ExitCode.NOT_PRESENT


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (("--path", "/run/media/deck/NOTHING"), "has no volume mounted at"),
        (("--device", "/dev/sdb5"), "steamos-mounter has not mounted /dev/sdb5"),
        (("--volume", "NOPE"), "no registered volume is called NOPE"),
    ],
    ids=["path", "device", "volume"],
)
def test_unmount_of_something_the_tool_does_not_own_exits_2(
    ctx, tmp_path, fake_runner, host_tree, argv, message
):
    given_host(ctx, tmp_path)
    host_tree.add_sysfs_facts()
    script_tree(fake_runner)

    result = run_cli(ctx, "unmount", *argv)

    assert result.code == ExitCode.USAGE
    assert message in result.err


def test_unmount_closes_an_open_mapping_with_nothing_mounted(
    ctx, personal_mounted, fake_runner
):
    unmounted = dict(PERSONAL_MOUNTED, mount=dict(PERSONAL_MOUNTED["mount"]))
    unmounted["mount"]["status"] = "unmounted"
    write_json(personal_mounted, PERSONAL_RECORD, unmounted)
    fake_runner.on((CRYPTSETUP, "close", PERSONAL_MAPPING), Answer())

    result = run_cli(ctx, "unmount", "--volume", "PERSONAL")

    assert (result.code, result.out) == (ExitCode.OK, f"closed {PERSONAL_MAPPING}\n")
    record = read_record(personal_mounted, PERSONAL_RECORD)
    assert record["unmounted_by_user"] == {"devnum": "252:0", "at": STAMP}
    assert record["mapping"] is None


def test_a_leaf_that_is_not_empty_is_left_in_place(ctx, personal_mounted, fake_runner):
    leaf = personal_mounted / PERSONAL_PATH.lstrip("/")
    (leaf / "left-behind").write_text("x", encoding="utf-8")
    fake_runner.on(readback_argv(PERSONAL_PATH), MOUNTED_ROW)
    fake_runner.on((UMOUNT, PERSONAL_PATH), Answer())
    fake_runner.on((CRYPTSETUP, "close", PERSONAL_MAPPING), Answer())

    assert run_cli(ctx, "unmount", "--volume", "PERSONAL").code == ExitCode.OK
    assert (leaf / "left-behind").is_file()


def test_unmount_by_path_skips_other_volumes(ctx, tmp_path, fake_runner, host_tree):
    given_host(ctx, tmp_path, registry=PERSONAL_REGISTRY)
    host_tree.add_sysfs_facts()
    script_tree(fake_runner)
    auto = record_dict(
        kind="auto",
        key="sdb5-8_21",
        name="MEDIABOX",
        mapping=None,
        mount=MEDIABOX_MOUNTED["mount"],
        source={"kname": "sdb5", "devnum": "8:21", "syspath": None},
    )
    write_json(tmp_path, SDB5_AUTO_RECORD, auto)

    result = run_cli(ctx, "unmount", "--path", "/run/media/deck/OTHER")

    assert result.code == ExitCode.USAGE
    assert "has no volume mounted at /run/media/deck/OTHER" in result.err


def test_a_unit_systemd_does_not_know_is_started(ctx, mediabox, fake_runner):
    fake_runner.on(
        show_argv(MEDIABOX_UNIT),
        Answer(stdout=b"LoadState=not-found\nActiveState=inactive\n"),
    )
    fake_runner.on(verb_argv("start", MEDIABOX_UNIT, block=True), Answer())
    script_table(fake_runner)

    run_cli(ctx, "mount", "--volume", "MEDIABOX")

    assert verb_argv("start", MEDIABOX_UNIT, block=True) in fake_runner.argvs


def test_an_unregistered_device_without_sysfs_is_not_attached(
    ctx, tmp_path, fake_runner
):
    given_host(ctx, tmp_path)
    script_tree(fake_runner)

    result = run_cli(ctx, "mount", "--device", "/dev/sdb5")

    assert result.code == ExitCode.NOT_PRESENT
    assert systemctl_calls(fake_runner) == []


def test_unmount_by_device_of_an_auto_volume(ctx, tmp_path, fake_runner, host_tree):
    given_host(ctx, tmp_path)
    host_tree.add_sysfs_facts()
    script_tree(fake_runner)
    auto = record_dict(
        kind="auto",
        key="sdb5-8_21",
        name="MEDIABOX",
        mapping=None,
        mount=dict(MEDIABOX_MOUNTED["mount"], created_dir=False),
        source={"kname": "sdb5", "devnum": "8:21", "syspath": None},
    )
    write_json(tmp_path, SDB5_AUTO_RECORD, auto)
    fake_runner.on(readback_argv(MEDIABOX_PATH), NOT_MOUNTED)

    result = run_cli(ctx, "unmount", "--device", "/dev/sdb5")

    assert result.out == f"unmounted MEDIABOX from {MEDIABOX_PATH}\n"
    assert read_record(tmp_path, SDB5_AUTO_RECORD)["state"] == "UnmountedByUser"
