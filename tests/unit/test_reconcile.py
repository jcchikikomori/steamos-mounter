"""reconcile: one pass of a registered or auto instance, end to end on fakes.

Design Doc "Device Classification and Routing" (executor steps, the
``UNLOCK_REGISTERED`` executor, the key unit interplay), "Runtime State
Records" (Write Rules, I006, D014, DD-10, DD-11), "Key Store", "Locks" (I007,
holo's lock), "Notifications", "Error Handling", DD-18, DD-19, DD-29 and
"Required Specific Tests" items 1, 2 and 9. Every command goes through the
fake runner; the registry, sysfs, key files, records and locks are real files
under ``tmp_path``, and the concurrency test takes real ``flock`` locks from
two threads (AC-035).
"""

import fcntl
import json
import logging
import os
import threading
from datetime import timedelta
from pathlib import Path

import pytest

from steamos_mounter import (
    reconcile,
    reconcile_mount,
    reconcile_report,
    reconcile_unlock,
    state,
)
from steamos_mounter.journal import NOTICE
from steamos_mounter.model import InstanceKind, Trigger, VolumeState
from steamos_mounter.records import TIMESTAMP_FORMAT, Record
from steamos_mounter.routing import Action, Route
from tests.helpers import builders
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture
from tests.helpers.flows import (
    ACTIVE,
    CRYPTSETUP,
    INACTIVE,
    LOGINCTL,
    LSBLK_ARGV,
    MOUNT,
    NTFS3G,
    PROBE,
    SYSTEMCTL,
    SYSTEMD_RUN,
    TABLE_ARGV,
    argvs_of,
    key_unit_show,
    known_os_set,
    lock_sdb1,
    make_keys_dir,
    make_mount_base,
    make_var_run,
    read_record,
    readback_argv,
    runtime_dirs,
    script_desktop_session,
    script_key_unit,
    script_lsblk,
    script_no_session,
    script_notify,
    sm_fields,
    write_key_file,
    write_registry,
)
from tests.helpers.host_tree import SysfsDevice

CLI = "sudo /opt/steamos-mounter/bin/steamos-mounter"
MEDIABOX_UUID = "01D95F1575592A30"
PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
MEDIABOX_DEVICE = f"/dev/disk/by-uuid/{MEDIABOX_UUID}"
PERSONAL_DEVICE = f"/dev/disk/by-uuid/{PERSONAL_UUID}"
MEDIABOX_PATH = "/run/media/deck/MEDIABOX"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
GAMES_PATH = "/run/media/deck/GAMES"
OBAMA_PATH = "/run/media/deck/OBAMA"
MEDIABOX_RECORD = "run/steamos-mounter/records/registered/01d95f1575592a30.json"
PERSONAL_RECORD = f"run/steamos-mounter/records/registered/{PERSONAL_UUID}.json"
SDB1_RECORD = "run/steamos-mounter/records/auto/sdb1-8_17.json"
SDC1_RECORD = "run/steamos-mounter/records/auto/sdc1-8_33.json"
DM0_RECORD = "run/steamos-mounter/records/auto/dm-0-252_0.json"
DM1_RECORD = "run/steamos-mounter/records/auto/dm-1-252_1.json"
MEDIABOX_LOCK = "run/steamos-mounter/locks/volume-01d95f1575592a30.lock"
SDB5_SYSPATH = "/sys/devices/host-tree/block/sdb/sdb5"
SDB1_SYSPATH = "/sys/devices/host-tree/block/sdb/sdb1"
DM0_SYSPATH = "/sys/devices/virtual/block/dm-0"
SDC1_SYSPATH = (
    "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-2/2-2:1.0/host1/"
    "target1:0:0/1:0:0:0/block/sdc/sdc1"
)
DM1_SYSPATH = "/sys/devices/virtual/block/dm-1"
DM0_UDISKS_NAME = "PAT4T4SHUAWEI_PERSONAL_4_3_2024"
DM1_UDISKS_NAME = "OBAMA_BACKUP_1_2_2025"
TOOL_MAPPING = f"steamos-mounter-{PERSONAL_UUID}"
REGISTERED_UNIT = (
    "steamos-mounter@dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52"
    "\\x2da297\\x2d31643c64724d.service"
)
KEY_UNIT = REGISTERED_UNIT.replace("steamos-mounter@", "steamos-mounter-key@")
KEY_UNIT_ID = "b" * 32
TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"
NTFS_RW_OPTIONS = "nosuid,nodev,uid=1000,gid=1000,umask=0022,windows_names"
EXFAT_OPTIONS = (
    "nosuid,nodev,uid=1000,gid=1000,umask=0022,iocharset=utf8,errors=remount-ro"
)
KERNEL_DIRTY = 'ntfs3(sdb5): volume is dirty and "force" flag is not set!'
REGISTRY = builders.registry_text([builders.MEDIABOX, builders.PERSONAL])
MEDIABOX_ONLY = builders.registry_text([builders.MEDIABOX])

NOT_MOUNTED = Answer.from_fixture("findmnt-sdb5-not-mounted.json")
REAL_TABLE = Answer.from_fixture("findmnt-real-list.json")
TABLE_WITH_MEDIABOX = Answer.from_fixture(
    "findmnt-list-with-mediabox.json", returncode=0
)
MEDIABOX_FUSE_RW = Answer.from_fixture("findmnt-mediabox-fuseblk-rw.json", returncode=0)
GAMES_EXFAT_RW = Answer.from_fixture("findmnt-games-exfat-rw.json", returncode=0)
OBAMA_NTFS3_RW = Answer.from_fixture("findmnt-obama-ntfs3-rw.json", returncode=0)
PERSONAL_NTFS3_RW = Answer.from_fixture("findmnt-personal-ntfs3-rw.json", returncode=0)


def edited_json(fixture: str, change) -> Answer:
    document = json.loads(load_fixture(fixture))
    change(document)
    return Answer(stdout=json.dumps(document).encode(), returncode=0)


def read_only(fixture: str) -> Answer:
    def to_ro(document):
        for row in document["filesystems"]:
            for key in ("vfs-options", "fs-options"):
                row[key] = ",".join(["ro", *row[key].split(",")[1:]])

    return edited_json(fixture, to_ro)


def table_with_mediabox_at(target: str) -> Answer:
    def move(document):
        document["filesystems"][-1]["target"] = target

    return edited_json("findmnt-list-with-mediabox.json", move)


def timestamp(ctx, seconds_ago: float) -> str:
    return (ctx.clock.now() - timedelta(seconds=seconds_ago)).strftime(TIMESTAMP_FORMAT)


def facts_text(*, drop: tuple[str, ...] = (), replace: dict[str, str] | None = None):
    """The Deck's sysfs-facts.txt with lines dropped or values replaced."""
    lines = []
    for line in load_fixture("sysfs-facts.txt").decode().splitlines():
        path, _, value = line.partition("=")
        if path in drop:
            continue
        value = (replace or {}).get(path, value)
        lines.append(f"{path}={value}")
    return "\n".join(lines) + "\n"


def write_record(root: Path, relative: str, **changes) -> None:
    path = root / relative
    path.write_text(json.dumps(builders.record_dict(**changes)), encoding="utf-8")


def mediabox_record(**changes):
    """A registered MEDIABOX record as an earlier pass left it."""
    values = {
        "kind": "registered",
        "key": "01d95f1575592a30",
        "name": "MEDIABOX",
        "state": "MountedRWDirty",
        "mapping": None,
        "source": {"kname": "sdb5", "devnum": "8:21", "syspath": SDB5_SYSPATH},
        "mount": {
            "status": "mounted",
            "target": MEDIABOX_PATH,
            "device": "/dev/sdb5",
            "devnum": "8:21",
            "driver": "ntfs-3g",
            "mode": "rw",
            "created_dir": True,
        },
    }
    values.update(changes)
    return values


@pytest.fixture(autouse=True)
def journal_levels(caplog):
    """NOTICE and INFO reach caplog (the root logger defaults to WARNING)."""
    caplog.set_level(logging.DEBUG)


@pytest.fixture
def deck(ctx, host_tree, tmp_path, fake_runner):
    """The owner's Deck: MEDIABOX and PERSONAL registered, the real tree and sysfs."""
    runtime_dirs(ctx)
    write_registry(tmp_path, REGISTRY)
    host_tree.add_sysfs_facts()
    host_tree.link_by_uuid(MEDIABOX_UUID, "sdb5")
    host_tree.link_by_uuid(PERSONAL_UUID, "sdb1")
    make_mount_base(tmp_path)
    make_var_run(tmp_path)
    known_os_set(tmp_path)
    return tmp_path


def script_dirty_mediabox(fake_runner, fake_kmsg, *, probe: int = 15, hook=None):
    """The MEDIABOX chain: probe, ntfs3 refused (kernel dirty line), ntfs-3g mounts."""
    fake_runner.on(PROBE, Answer(returncode=probe), hook=hook)
    fake_runner.on(MOUNT, Answer(returncode=32))
    fake_runner.on(NTFS3G, Answer())
    fake_runner.on(readback_argv(MEDIABOX_PATH), NOT_MOUNTED, MEDIABOX_FUSE_RW)
    fake_kmsg.queue(KERNEL_DIRTY)


def add_dolphin_sysfs(host_tree, *, sdc1_holders=("dm-1",)) -> None:
    """sdc (removable), sdc1 BitLocker 8:33, dm-1 252:1 with a udisks name."""
    host_tree.add_block(SysfsDevice(kname="sdc", devnum="8:32"))
    host_tree.add_block(
        SysfsDevice(
            kname="sdc1",
            devnum="8:33",
            parent="sdc",
            syspath=SDC1_SYSPATH,
            holders=sdc1_holders,
        )
    )
    host_tree.add_block(
        SysfsDevice(
            kname="dm-1", devnum="252:1", slaves=("sdc1",), dm_name=DM1_UDISKS_NAME
        )
    )


def script_obama_chain(fake_runner) -> None:
    fake_runner.on(PROBE, Answer())
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback_argv(OBAMA_PATH), OBAMA_NTFS3_RW)


def outcome_logs(caplog, state: str) -> list[logging.LogRecord]:
    return [
        record
        for record in caplog.records
        if sm_fields(record).get("SM_STATE") == state
        and sm_fields(record).get("SM_EVENT") == "reconcile"
    ]


# --- journal-only actions ---------------------------------------------------------


def test_bad_kname_is_rejected_before_any_command(ctx, deck, fake_runner, caplog):
    """AC-030: a kname outside ^[a-z0-9-]+$ is refused; nothing runs."""
    outcome = reconcile.run(
        ctx, InstanceKind.AUTO, "/sys/devices/x/block/sdb/SDB5", Trigger.START
    )

    assert outcome.route.action is Action.REJECT
    assert (outcome.state, outcome.reason) == (None, "invalid kernel device name")
    assert fake_runner.argvs == []
    assert [r.levelno for r in caplog.records if "SDB5" in r.getMessage()] == [
        logging.WARNING
    ]


def test_missing_by_uuid_link_is_ignored(ctx, deck, fake_runner):
    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, "/dev/disk/by-uuid/0000-1111", Trigger.START
    )

    assert outcome.route.action is Action.IGNORE
    assert outcome.route.reason == "device not present"
    assert fake_runner.argvs == []


def test_by_uuid_link_outside_dev_is_rejected(ctx, deck, fake_runner, host_tree):
    link = host_tree.path("/dev/disk/by-uuid/2222-3333")
    target = host_tree.path("/srv/sdb9")
    target.parent.mkdir(parents=True)
    target.touch()
    link.symlink_to(target)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, "/dev/disk/by-uuid/2222-3333", Trigger.START
    )

    assert outcome.route.action is Action.REJECT
    assert fake_runner.argvs == []


def test_auto_instance_of_a_registered_partition_yields_without_a_record(
    ctx, deck, fake_runner, caplog
):
    script_lsblk(fake_runner, "lsblk-columns-tree.json")

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDB5_SYSPATH, Trigger.START)

    assert outcome.route.action is Action.YIELD
    assert outcome.state is None
    assert fake_runner.argvs == [LSBLK_ARGV]
    assert os.listdir(deck / "run/steamos-mounter/records/auto") == []
    notices = [r for r in caplog.records if r.levelno == NOTICE]
    assert sm_fields(notices[-1])["SM_EVENT"] == "reconcile"
    assert sm_fields(notices[-1])["SM_DEVICE"] == "/dev/sdb5"


def test_ext4_partition_is_ignored(ctx, deck, fake_runner):
    script_lsblk(fake_runner, "lsblk-columns-tree.json")

    outcome = reconcile.run(
        ctx, InstanceKind.AUTO, "/sys/devices/host-tree/block/sda/sda1", Trigger.START
    )

    assert (outcome.route.action, outcome.route.reason) == (
        Action.IGNORE,
        "ext4: SteamOS handles it",
    )
    assert os.listdir(deck / "run/steamos-mounter/records/auto") == []


def test_unusable_registry_fails_closed_with_an_error(ctx, deck, fake_runner, caplog):
    (deck / "etc/steamos-mounter/config.toml").chmod(0o666)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert outcome.route.action is Action.FAIL_CLOSED
    assert not (deck / MEDIABOX_RECORD).exists()
    assert any(
        r.levelno == logging.ERROR and "registry unreadable" in r.getMessage()
        for r in caplog.records
    )


def test_own_mapping_is_left_to_its_opener(ctx, host_tree, tmp_path, fake_runner):
    runtime_dirs(ctx)
    write_registry(tmp_path, REGISTRY)
    host_tree.add_sysfs_facts(
        facts_text(replace={"/sys/block/dm-0/dm/name": TOOL_MAPPING})
    )
    script_lsblk(fake_runner, "lsblk-columns-tree.json")

    outcome = reconcile.run(ctx, InstanceKind.AUTO, DM0_SYSPATH, Trigger.START)

    assert outcome.route.action is Action.OWN_MAPPING
    assert fake_runner.argvs == [LSBLK_ARGV]
    assert not (tmp_path / DM0_RECORD).exists()


# --- delegation (DD-12, D006, I006) -----------------------------------------------


def test_dm_instance_delegates_with_a_non_blocking_reload(ctx, deck, fake_runner):
    """EARS: a unit running reconcile never starts a job or waits on one."""
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on((SYSTEMCTL, "show"), Answer(stdout=ACTIVE.encode()))
    fake_runner.on((SYSTEMCTL, "reload"), Answer())

    outcome = reconcile.run(ctx, InstanceKind.AUTO, DM0_SYSPATH, Trigger.START)

    assert outcome.route.action is Action.DELEGATE
    assert outcome.route.delegate_unit == REGISTERED_UNIT
    assert (outcome.state, outcome.reason) == (None, "reloaded")
    assert argvs_of(fake_runner, SYSTEMCTL)[1] == (
        SYSTEMCTL,
        "reload",
        "--no-block",
        "--",
        REGISTERED_UNIT,
    )
    assert not any("start" in argv for argv in fake_runner.argvs)
    assert not (deck / DM0_RECORD).exists()
    assert argvs_of(fake_runner, MOUNT) == []


def test_delegate_absent_writes_the_minimal_record_and_one_warning(
    ctx, deck, fake_runner, caplog
):
    """I006: an inactive partition instance is never started; list still sees it."""
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on((SYSTEMCTL, "show"), Answer(stdout=INACTIVE.encode()))

    outcome = reconcile.run(ctx, InstanceKind.AUTO, DM0_SYSPATH, Trigger.START)

    assert (outcome.state, outcome.reason) == (
        VolumeState.NOT_MOUNTED,
        "no_partition_instance",
    )
    assert [argv[1] for argv in argvs_of(fake_runner, SYSTEMCTL)] == ["show"]
    record = read_record(deck, DM0_RECORD)
    assert record["kind"] == "auto"
    assert record["key"] == "dm-0-252_0"
    assert record["name"] == "PERSONAL"
    assert record["state"] == "NotMounted"
    assert record["reason"] == "no_partition_instance"
    assert record["next_step"] == f"{CLI} mount --device /dev/sdb1"
    assert (record["mapping"], record["mount"]) == (None, None)
    assert record["source"]["kname"] == "dm-0"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert ["no partition instance" in r.getMessage() for r in warnings] == [True]
    # Lock key of anything routed to a registered volume: the registry UUID (I007).
    assert (deck / f"run/steamos-mounter/locks/volume-{PERSONAL_UUID}.lock").exists()


def test_delegate_absent_for_an_unregistered_container_names_the_inner_label(
    ctx, host_tree, tmp_path, fake_runner
):
    runtime_dirs(ctx)
    write_registry(tmp_path, None)
    add_dolphin_sysfs(host_tree)
    script_lsblk(fake_runner, "lsblk-tree-dolphin-unregistered.json")
    fake_runner.on((SYSTEMCTL, "show"), Answer(stdout=b"LoadState=not-found\n"))

    reconcile.run(ctx, InstanceKind.AUTO, DM1_SYSPATH, Trigger.START)

    record = read_record(tmp_path, DM1_RECORD)
    assert record["name"] == "OBAMA"
    assert record["next_step"] == f"{CLI} mount --device /dev/sdc1"
    lock = "run/steamos-mounter/locks/volume-7c1e4b2a-9d3f-4e5a-8b6c-0d1e2f3a4b5c.lock"
    assert (tmp_path / lock).exists()


# --- skip locked (AC-025) and refusals ---------------------------------------------


def test_locked_unregistered_container_records_locked(
    ctx, host_tree, tmp_path, fake_runner
):
    runtime_dirs(ctx)
    write_registry(tmp_path, MEDIABOX_ONLY)
    known_os_set(tmp_path)
    host_tree.add_sysfs_facts(facts_text(drop=("/sys/class/block/sdb1/holders",)))
    script_lsblk(fake_runner, "lsblk-tree-personal-locked.json")

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDB1_SYSPATH, Trigger.START)

    assert outcome.route.action is Action.SKIP_LOCKED
    assert outcome.state is VolumeState.LOCKED
    record = read_record(tmp_path, SDB1_RECORD)
    assert record["state"] == "Locked"
    assert record["name"] == "PAT4T4SHUAWEI PERSONAL 4_3_2024"
    assert (
        record["next_step"] == "Unlock it in Dolphin; it mounts by itself after that."
    )
    assert record["source"] == {
        "kname": "sdb1",
        "devnum": "8:17",
        "syspath": SDB1_SYSPATH,
    }
    assert record["mount"] is None
    assert fake_runner.argvs == [LSBLK_ARGV]


def test_fstype_mismatch_records_mount_failed_and_notifies(
    ctx, deck, fake_runner, caplog
):
    write_registry(
        deck,
        builders.registry_text(
            [builders.RegistryVolume("MEDIABOX", MEDIABOX_UUID, MEDIABOX_PATH, "exfat")]
        ),
    )
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    script_desktop_session(fake_runner)
    script_notify(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert outcome.route.action is Action.REFUSE_REGISTERED
    assert (outcome.state, outcome.reason) == (
        VolumeState.MOUNT_FAILED,
        "fstype_mismatch",
    )
    record = read_record(deck, MEDIABOX_RECORD)
    assert (record["state"], record["reason"]) == ("MountFailed", "fstype_mismatch")
    assert record["next_step"] == "Check that this is the right drive."
    assert argvs_of(fake_runner, MOUNT) == []
    [notify] = argvs_of(fake_runner, SYSTEMD_RUN)
    assert "MEDIABOX could not be mounted" in notify
    assert any(
        r.levelno == logging.ERROR and sm_fields(r).get("SM_STATE") == "MountFailed"
        for r in caplog.records
    )


def test_no_notification_without_a_desktop_session(ctx, deck, fake_runner):
    """DD-19: the logind half decides; NONE sends nothing."""
    write_registry(
        deck,
        builders.registry_text(
            [builders.RegistryVolume("MEDIABOX", MEDIABOX_UUID, MEDIABOX_PATH, "exfat")]
        ),
    )
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    script_no_session(fake_runner)

    reconcile.run(ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START)

    assert len(argvs_of(fake_runner, LOGINCTL)) == 1
    assert argvs_of(fake_runner, SYSTEMD_RUN) == []


# --- the mount executor -----------------------------------------------------------


def test_write_ahead_pending_before_the_first_chain_call(
    ctx, deck, fake_runner, fake_kmsg
):
    """DD-10, EARS: the target is in the record before a chain step runs."""
    seen = []

    def snapshot(_command):
        seen.append(read_record(deck, MEDIABOX_RECORD))

    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_dirty_mediabox(fake_runner, fake_kmsg, hook=snapshot)
    script_desktop_session(fake_runner)
    script_notify(fake_runner)

    reconcile.run(ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START)

    [ahead] = seen
    assert ahead["state"] == "Mounting"
    assert ahead["mount"]["status"] == "pending"
    assert ahead["mount"]["target"] == MEDIABOX_PATH
    assert ahead["mount"]["device"] == "/dev/sdb5"
    assert ahead["source"]["devnum"] == "8:21"
    final = read_record(deck, MEDIABOX_RECORD)
    assert final["mount"]["status"] == "mounted"
    assert final["mount"]["created_dir"] is True


def test_dirty_mediabox_record_journal_and_notification(
    ctx, deck, fake_runner, fake_kmsg, caplog
):
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_dirty_mediabox(fake_runner, fake_kmsg)
    script_desktop_session(fake_runner)
    script_notify(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert (outcome.state, outcome.reason) == (VolumeState.MOUNTED_RW_DIRTY, "dirty")
    record = read_record(deck, MEDIABOX_RECORD)
    assert record["unit"] == (
        "steamos-mounter@dev-disk-by\\x2duuid-01D95F1575592A30.service"
    )
    assert record["invocation_id"] == "0f6c9c1e5c7a4c51a0a5f3f3b2b6d7e8"
    assert record["trigger"] == "start"
    assert record["warning"] == (
        "MEDIABOX is dirty: Windows did not close it cleanly. It is mounted"
        " read-write with ntfs-3g."
    )
    assert record["attempt"]["probe"] == {"code": 15, "class": "dirty"}
    notices = outcome_logs(caplog, "MountedRWDirty")
    assert [r.levelno for r in notices] == [NOTICE, logging.WARNING]
    assert sm_fields(notices[0])["SM_VOLUME"] == "MEDIABOX"
    assert sm_fields(notices[0])["SM_UUID"] == MEDIABOX_UUID
    assert len(argvs_of(fake_runner, SYSTEMD_RUN)) == 1


def test_start_then_reload_is_a_no_op(ctx, deck, fake_runner, fake_kmsg):
    """Required Specific Tests 2, AC-035: one mount; the second pass changes nothing."""
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE, TABLE_WITH_MEDIABOX)
    script_dirty_mediabox(fake_runner, fake_kmsg)
    script_desktop_session(fake_runner)
    script_notify(fake_runner)

    reconcile.run(ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START)
    first = read_record(deck, MEDIABOX_RECORD)
    second = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.RELOAD
    )

    assert (second.state, second.reason) == (VolumeState.MOUNTED_RW_DIRTY, "dirty")
    assert len(argvs_of(fake_runner, PROBE)) == 1
    assert len(argvs_of(fake_runner, NTFS3G)) == 1
    assert len(argvs_of(fake_runner, SYSTEMD_RUN)) == 1  # no second notification
    record = read_record(deck, MEDIABOX_RECORD)
    assert record["trigger"] == "reload"
    assert record["attempt"] == first["attempt"]
    assert record["mount"] == first["mount"]


def test_already_mounted_after_a_crash_adopts_the_pending_mount(ctx, deck, fake_runner):
    """A pass that died after mounting left ``pending``; findmnt is the truth."""
    pending = mediabox_record(
        state="MountFailed", reason="probe_failed", warning=None, next_step=None
    )
    pending["mount"] = dict(pending["mount"], status="pending", driver=None, mode=None)
    write_record(deck, MEDIABOX_RECORD, **pending)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, TABLE_WITH_MEDIABOX)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.RELOAD
    )

    assert outcome.state is VolumeState.MOUNTED_RW
    record = read_record(deck, MEDIABOX_RECORD)
    assert (record["state"], record["reason"]) == ("MountedRW", None)
    assert record["mount"]["status"] == "mounted"
    assert (record["mount"]["driver"], record["mount"]["mode"]) == ("ntfs-3g", "rw")
    assert argvs_of(fake_runner, PROBE) == []


def test_no_remount_after_user_unmount(ctx, deck, fake_runner, fake_kmsg):
    """AC-033: a reload does not undo the owner's unmount; a start does."""
    write_record(
        deck,
        MEDIABOX_RECORD,
        **mediabox_record(
            state="UnmountedByUser",
            reason=None,
            warning=None,
            next_step=None,
            unmounted_by_user={"devnum": "8:21", "at": timestamp(ctx, 600)},
        ),
    )
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE, repeat=True)
    script_dirty_mediabox(fake_runner, fake_kmsg)
    script_desktop_session(fake_runner)
    script_notify(fake_runner)

    reloaded = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.RELOAD
    )

    assert reloaded.state is VolumeState.UNMOUNTED_BY_USER
    assert argvs_of(fake_runner, PROBE) == []
    assert read_record(deck, MEDIABOX_RECORD)["unmounted_by_user"] is not None

    started = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert started.state is VolumeState.MOUNTED_RW_DIRTY
    assert read_record(deck, MEDIABOX_RECORD)["unmounted_by_user"] is None


@pytest.mark.parametrize(
    ("flag_devnum", "mounts"),
    [("252:7", True), ("252:1", False)],
    ids=["new-dm-clears-it", "same-dm-keeps-it"],
)
def test_user_unmount_is_scoped_to_the_mapping_devnum(
    ctx, host_tree, tmp_path, fake_runner, flag_devnum, mounts
):
    """DD-11: a new foreign unlock (a new dm-*) is a new owner action."""
    runtime_dirs(ctx)
    write_registry(tmp_path, None)
    known_os_set(tmp_path)
    make_mount_base(tmp_path)
    add_dolphin_sysfs(host_tree)
    write_record(
        tmp_path,
        SDC1_RECORD,
        kind="auto",
        key="sdc1-8_33",
        name="OBAMA",
        state="UnmountedByUser",
        mount=None,
        mapping=None,
        unmounted_by_user={"devnum": flag_devnum, "at": timestamp(ctx, 60)},
    )
    script_lsblk(fake_runner, "lsblk-tree-dolphin-unregistered.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_obama_chain(fake_runner)

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.RELOAD)

    assert (outcome.state is VolumeState.MOUNTED_RW) is mounts
    assert bool(argvs_of(fake_runner, PROBE)) is mounts
    record = read_record(tmp_path, SDC1_RECORD)
    assert (record["unmounted_by_user"] is None) is mounts


@pytest.mark.parametrize("seconds_ago", [30, -30, 120], ids=["past", "skew", "edge"])
def test_fresh_cli_request_turns_reload_into_cli_and_is_cleared(
    ctx, deck, fake_runner, fake_kmsg, seconds_ago
):
    """D014: a fresh marker overrides the user-unmount rule like a start would."""
    write_record(
        deck,
        MEDIABOX_RECORD,
        **mediabox_record(
            state="UnmountedByUser",
            unmounted_by_user={"devnum": "8:21", "at": timestamp(ctx, 600)},
            cli_request={
                "token": "0123456789abcdef",
                "at": timestamp(ctx, seconds_ago),
            },
        ),
    )
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_dirty_mediabox(fake_runner, fake_kmsg)
    script_desktop_session(fake_runner)
    script_notify(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.RELOAD
    )

    assert outcome.state is VolumeState.MOUNTED_RW_DIRTY
    record = read_record(deck, MEDIABOX_RECORD)
    assert record["trigger"] == "cli"
    assert (record["cli_request"], record["unmounted_by_user"]) == (None, None)


@pytest.mark.parametrize("at", ["stale", "garbage", None], ids=str)
def test_stale_cli_request_is_cleared_and_ignored(ctx, deck, fake_runner, at):
    stamp = {"stale": timestamp(ctx, 121), "garbage": "yesterday", None: None}[at]
    write_record(
        deck,
        MEDIABOX_RECORD,
        **mediabox_record(
            state="UnmountedByUser",
            unmounted_by_user={"devnum": "8:21", "at": timestamp(ctx, 600)},
            cli_request={"token": "0123456789abcdef", "at": stamp},
        ),
    )
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.RELOAD
    )

    assert outcome.state is VolumeState.UNMOUNTED_BY_USER
    assert argvs_of(fake_runner, PROBE) == []
    record = read_record(deck, MEDIABOX_RECORD)
    assert (record["trigger"], record["cli_request"]) == ("reload", None)


def test_start_trigger_also_clears_a_cli_request(ctx, deck, fake_runner):
    write_record(
        deck,
        MEDIABOX_RECORD,
        **mediabox_record(cli_request={"token": "0123456789abcdef", "at": "x"}),
    )
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, TABLE_WITH_MEDIABOX)

    reconcile.run(ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START)

    record = read_record(deck, MEDIABOX_RECORD)
    assert (record["trigger"], record["cli_request"]) == ("start", None)


def test_mounted_elsewhere_recorded(ctx, deck, fake_runner, caplog):
    """AC-034: mounted at another target -> recorded, logged, not mounted again."""
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, table_with_mediabox_at("/run/media/deck/MEDIABOX1"))

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert outcome.state is VolumeState.MOUNTED_ELSEWHERE
    assert "/run/media/deck/MEDIABOX1" in outcome.reason
    assert argvs_of(fake_runner, PROBE) == []
    record = read_record(deck, MEDIABOX_RECORD)
    assert (record["state"], record["reason"], record["mount"]) == (
        "MountedElsewhere",
        None,
        None,
    )
    assert record["next_step"] == (
        f"Unmount it there, then run {CLI} mount --volume MEDIABOX to use the fixed"
        " path."
    )
    [notice] = outcome_logs(caplog, "MountedElsewhere")
    assert notice.levelno == NOTICE
    assert "/run/media/deck/MEDIABOX1" in sm_fields(notice)["SM_REASON"]
    assert argvs_of(fake_runner, LOGINCTL) == []


def test_mounted_elsewhere_marks_a_previous_own_mount_unmounted(ctx, deck, fake_runner):
    write_record(deck, MEDIABOX_RECORD, **mediabox_record())
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, table_with_mediabox_at("/run/media/deck/MEDIABOX1"))

    reconcile.run(ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.RELOAD)

    record = read_record(deck, MEDIABOX_RECORD)
    assert record["mount"]["status"] == "unmounted"
    assert record["mount"]["target"] == MEDIABOX_PATH


@pytest.mark.parametrize("holder", ["dm-3", "md127"], ids=["lvm", "md"])
def test_foreign_holders_are_mounted_elsewhere_held(
    ctx, host_tree, tmp_path, fake_runner, caplog, holder
):
    """ADR-0002 D4: LVM or md on the partition holds it; nothing is mounted."""
    runtime_dirs(ctx)
    write_registry(tmp_path, REGISTRY)
    host_tree.add_sysfs_facts(
        facts_text(replace={"/sys/class/block/sdb5/holders": holder})
    )
    host_tree.link_by_uuid(MEDIABOX_UUID, "sdb5")
    make_mount_base(tmp_path)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert outcome.state is VolumeState.MOUNTED_ELSEWHERE
    assert holder in outcome.reason
    record = read_record(tmp_path, MEDIABOX_RECORD)
    assert (record["state"], record["reason"]) == ("MountedElsewhere", "held")
    assert argvs_of(fake_runner, PROBE) == []


def test_a_crypt_holder_is_part_of_the_volume(
    ctx, host_tree, tmp_path, fake_runner, fake_kmsg
):
    """ADR-0002 D4 I013: a crypt mapping is the volume's own stack, not a holder."""
    runtime_dirs(ctx)
    write_registry(tmp_path, REGISTRY)
    host_tree.add_sysfs_facts(
        facts_text(replace={"/sys/class/block/sdb5/holders": "dm-0"})
    )
    host_tree.link_by_uuid(MEDIABOX_UUID, "sdb5")
    make_mount_base(tmp_path)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_dirty_mediabox(fake_runner, fake_kmsg)
    script_no_session(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert outcome.state is VolumeState.MOUNTED_RW_DIRTY


def test_concurrent_reconcile_one_mount(ctx, deck, fake_runner, fake_kmsg):
    """AC-035: two passes at once, real flock on the volume lock -> one mount."""
    both_read_the_tree = threading.Barrier(2, timeout=10)
    fake_runner.on(
        LSBLK_ARGV,
        Answer.from_fixture("lsblk-columns-tree.json"),
        hook=lambda _command: both_read_the_tree.wait(),
        repeat=True,
    )
    fake_runner.on(TABLE_ARGV, REAL_TABLE, TABLE_WITH_MEDIABOX)
    script_dirty_mediabox(fake_runner, fake_kmsg)
    script_desktop_session(fake_runner)
    script_notify(fake_runner)
    outcomes = []

    def one_pass(trigger):
        outcomes.append(
            reconcile.run(ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, trigger)
        )

    threads = [
        threading.Thread(target=one_pass, args=(trigger,))
        for trigger in (Trigger.START, Trigger.RELOAD)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert [outcome.state for outcome in outcomes] == [VolumeState.MOUNTED_RW_DIRTY] * 2
    assert len(argvs_of(fake_runner, PROBE)) == 1
    assert len(argvs_of(fake_runner, NTFS3G)) == 1
    lock = os.open(deck / MEDIABOX_LOCK, os.O_RDWR)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released by both
    finally:
        os.close(lock)


def test_holo_lock_is_taken_for_the_partition(ctx, deck, fake_runner, fake_kmsg):
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_dirty_mediabox(fake_runner, fake_kmsg)
    script_no_session(fake_runner)

    reconcile.run(ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START)

    assert os.listdir(deck / "var/run") == ["jupiter-automount-sdb5.lock"]


def test_holo_lock_for_a_mapping_is_its_backing_partition(
    ctx, host_tree, tmp_path, fake_runner
):
    runtime_dirs(ctx)
    write_registry(tmp_path, None)
    known_os_set(tmp_path)
    make_mount_base(tmp_path)
    make_var_run(tmp_path)
    add_dolphin_sysfs(host_tree)
    script_lsblk(fake_runner, "lsblk-tree-dolphin-unregistered.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_obama_chain(fake_runner)

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.RELOAD)

    assert outcome.state is VolumeState.MOUNTED_RW
    assert os.listdir(tmp_path / "var/run") == ["jupiter-automount-sdc1.lock"]


def test_no_holo_lock_for_a_kname_holo_could_not_build(
    ctx, host_tree, tmp_path, fake_runner
):
    """Locks: holo's regex is ^[a-z0-9]+$, so a kname with a dash gets none."""
    runtime_dirs(ctx)
    write_registry(
        tmp_path,
        builders.registry_text(
            [
                builders.RegistryVolume(
                    "DASH", "ABCD-1234", "/run/media/deck/DASH", "exfat"
                )
            ]
        ),
    )
    make_mount_base(tmp_path)
    make_var_run(tmp_path)
    host_tree.add_block(SysfsDevice(kname="xd-a", devnum="8:48"))
    host_tree.add_block(SysfsDevice(kname="xd-a1", devnum="8:49", parent="xd-a"))
    host_tree.link_by_uuid("ABCD-1234", "xd-a1")
    tree = builders.lsblk_tree(
        [
            builders.lsblk_device(
                "xd-a",
                {
                    "type": "disk",
                    "hotplug": True,
                    "maj:min": "8:48",
                    "children": [
                        builders.lsblk_device(
                            "xd-a1",
                            {
                                "fstype": "exfat",
                                "uuid": "ABCD-1234",
                                "pkname": "xd-a",
                                "hotplug": True,
                                "maj:min": "8:49",
                            },
                        )
                    ],
                },
            )
        ]
    )
    fake_runner.on(LSBLK_ARGV, Answer(stdout=json.dumps(tree).encode()))
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    fake_runner.on(MOUNT, Answer())

    def dash_readback(document):
        row = document["filesystems"][0]
        row.update(target="/run/media/deck/DASH", source="/dev/xd-a1")
        row["maj:min"] = "8:49"

    fake_runner.on(
        readback_argv("/run/media/deck/DASH"),
        edited_json("findmnt-games-exfat-rw.json", dash_readback),
    )

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, "/dev/disk/by-uuid/ABCD-1234", Trigger.START
    )

    assert outcome.state is VolumeState.MOUNTED_RW
    assert os.listdir(tmp_path / "var/run") == []


def test_busy_holo_lock_records_device_busy(ctx, deck, fake_runner, fake_clock):
    """Locks: holo's lock is waited for at most 5 s, never past the deadline."""
    holo = os.open(deck / "var/run/jupiter-automount-sdb5.lock", os.O_RDWR | os.O_CREAT)
    fcntl.flock(holo, fcntl.LOCK_EX)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE, hook=lambda _c: fake_clock.advance(59.8))
    script_no_session(fake_runner)
    try:
        outcome = reconcile.run(
            ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
        )
    finally:
        os.close(holo)

    assert (outcome.state, outcome.reason) == (VolumeState.MOUNT_FAILED, "device_busy")
    record = read_record(deck, MEDIABOX_RECORD)
    assert (record["state"], record["reason"]) == ("MountFailed", "device_busy")
    assert record["next_step"] == f"Wait, then run {CLI} mount --volume MEDIABOX."
    assert record["mount"]["status"] == "unmounted"
    assert argvs_of(fake_runner, PROBE) == []


def test_probe_time_is_reserved_in_the_deadline(ctx, deck, fake_runner, fake_clock):
    """The 20 s probe is never started when it could end past the deadline."""
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE, hook=lambda _c: fake_clock.advance(41))
    script_no_session(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert outcome.state is VolumeState.MOUNT_TIMED_OUT
    assert argvs_of(fake_runner, PROBE) == []
    record = read_record(deck, MEDIABOX_RECORD)
    assert (record["state"], record["reason"]) == ("MountTimedOut", None)
    assert record["next_step"] == f"Run {CLI} mount --volume MEDIABOX to try again."


def exfat_world(ctx, host_tree, tmp_path, fake_runner) -> None:
    runtime_dirs(ctx)
    write_registry(tmp_path, None)
    known_os_set(tmp_path)
    make_mount_base(tmp_path)
    host_tree.add_block(SysfsDevice(kname="sdc", devnum="8:32"))
    host_tree.add_block(
        SysfsDevice(kname="sdc1", devnum="8:33", parent="sdc", syspath=SDC1_SYSPATH)
    )
    script_lsblk(fake_runner, "lsblk-tree-with-exfat-sdc1.json")


def test_no_probe_reserve_for_a_chain_without_a_probe(
    ctx, host_tree, tmp_path, fake_runner, fake_clock
):
    exfat_world(ctx, host_tree, tmp_path, fake_runner)
    fake_runner.on(TABLE_ARGV, REAL_TABLE, hook=lambda _c: fake_clock.advance(41))
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback_argv(GAMES_PATH), GAMES_EXFAT_RW)

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.START)

    assert outcome.state is VolumeState.MOUNTED_RW


def test_failed_auto_mount_records_unknown_with_the_tool_message(
    ctx, host_tree, tmp_path, fake_runner
):
    """AC-018; auto records carry their own next step: --device, not --volume."""
    exfat_world(ctx, host_tree, tmp_path, fake_runner)
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    fake_runner.on(
        MOUNT, Answer(returncode=32, stderr=b"mount: /run/media/deck/GAMES: bad.\n")
    )
    fake_runner.on(readback_argv(GAMES_PATH), NOT_MOUNTED)
    script_desktop_session(fake_runner)
    script_notify(fake_runner)

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.START)

    assert outcome.state is VolumeState.MOUNT_FAILED
    record = read_record(tmp_path, SDC1_RECORD)
    assert (record["state"], record["reason"]) == ("MountFailed", "unknown")
    assert record["warning"] == (
        "GAMES could not be mounted: mount: /run/media/deck/GAMES: bad."
    )
    assert record["next_step"] == (
        f"See the journal, then run {CLI} mount --device /dev/sdc1."
    )
    assert record["mount"]["status"] == "unmounted"
    [notify] = argvs_of(fake_runner, SYSTEMD_RUN)
    assert notify[notify.index("-u") + 1] == "critical"


def test_no_free_name_records_mount_failed(ctx, host_tree, tmp_path, fake_runner):
    """Names and Paths: GAMES and GAMES-2 to -99 all taken -> no_free_name."""
    exfat_world(ctx, host_tree, tmp_path, fake_runner)
    for name in ["GAMES", *(f"GAMES-{n}" for n in range(2, 100))]:
        (tmp_path / "run/media/deck" / name / "keep").mkdir(parents=True)
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_no_session(fake_runner)

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.START)

    assert (outcome.state, outcome.reason) == (VolumeState.MOUNT_FAILED, "no_free_name")
    record = read_record(tmp_path, SDC1_RECORD)
    assert record["next_step"] == (
        "Remove unused empty folders where drives are mounted, then replug the drive."
    )
    assert record["mount"] is None
    assert argvs_of(fake_runner, MOUNT) == []


def test_auto_name_skips_a_mount_point_and_a_registered_path(
    ctx, host_tree, tmp_path, fake_runner
):
    """AC-028: a taken name gets -2; a registered fixed path is taken too."""
    exfat_world(ctx, host_tree, tmp_path, fake_runner)
    write_registry(
        tmp_path,
        builders.registry_text(
            [
                builders.RegistryVolume(
                    "OTHER", "AAAA-BBBB", "/run/media/deck/GAMES-2", "vfat"
                )
            ]
        ),
    )

    def games_mounted(document):
        row = dict(document["filesystems"][-1], target=GAMES_PATH, source="/dev/sdz1")
        document["filesystems"].append(row)

    fake_runner.on(TABLE_ARGV, edited_json("findmnt-real-list.json", games_mounted))
    fake_runner.on(MOUNT, Answer())

    def games_3(document):
        document["filesystems"][0]["target"] = "/run/media/deck/GAMES-3"

    fake_runner.on(
        readback_argv("/run/media/deck/GAMES-3"),
        edited_json("findmnt-games-exfat-rw.json", games_3),
    )

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.START)

    assert outcome.state is VolumeState.MOUNTED_RW
    assert argvs_of(fake_runner, MOUNT)[0][-1] == "/run/media/deck/GAMES-3"


def test_refused_fixed_path_records_mount_failed(ctx, deck, fake_runner):
    (deck / "run/media/deck/MEDIABOX/somebody").mkdir(parents=True)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_no_session(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert (outcome.state, outcome.reason) == (VolumeState.MOUNT_FAILED, "unknown")
    record = read_record(deck, MEDIABOX_RECORD)
    assert record["warning"] == (
        f"{MEDIABOX_PATH} cannot be used: path is a directory that is not empty."
    )
    assert record["mount"]["status"] == "unmounted"
    assert argvs_of(fake_runner, PROBE) == []


def test_existing_empty_fixed_path_is_not_marked_created(
    ctx, deck, fake_runner, fake_kmsg
):
    """DD-26: only a directory this tool made is removed again at teardown."""
    (deck / "run/media/deck/MEDIABOX").mkdir()
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_dirty_mediabox(fake_runner, fake_kmsg)
    script_no_session(fake_runner)

    reconcile.run(ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START)

    mount = read_record(deck, MEDIABOX_RECORD)["mount"]
    assert (mount["status"], mount["created_dir"]) == ("mounted", False)


def test_personal_probe_13_ends_read_only_with_a_chkdsk_next_step(
    ctx, deck, fake_runner
):
    """Owner's real PERSONAL: probe 13 is unsafe, ntfs-3g refuses, ntfs3 ro mounts."""
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    fake_runner.on(
        PROBE,
        Answer(returncode=13, stderr=b"$MFTMirr does not match $MFT (record 3).\n"),
    )
    fake_runner.on(NTFS3G, Answer(returncode=13, stderr=b"Failed to mount.\n"))
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(
        readback_argv(PERSONAL_PATH),
        NOT_MOUNTED,
        read_only("findmnt-personal-ntfs3-rw.json"),
    )
    script_desktop_session(fake_runner)
    script_notify(fake_runner)
    script_key_unit(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.START
    )

    assert outcome.route.action is Action.MOUNT_INNER_REGISTERED
    assert (outcome.state, outcome.reason) == (VolumeState.MOUNTED_RO, "unsafe")
    record = read_record(deck, PERSONAL_RECORD)
    assert record["next_step"] == (
        "Shut Windows down fully (no Fast Startup), then run chkdsk /f on it in"
        " Windows."
    )
    assert record["attempt"]["probe"] == {"code": 13, "class": "unsafe"}
    assert record["attempt"]["skipped"] == [
        {"driver": "ntfs3", "mode": "rw", "detail": "probe: unsafe"}
    ]
    assert [step["result"] for step in record["attempt"]["steps"]] == [
        "refused",
        "mounted",
    ]
    assert record["mount"]["mode"] == "ro"
    assert record["mount"]["device"] == "/dev/dm-0"
    assert record["mapping"]["opened_by"] == "other"
    assert record["mapping"]["name"] == DM0_UDISKS_NAME


def test_ntfs3g_rw_without_dirty_evidence_warns_with_the_reason(ctx, deck, fake_runner):
    """NFR-14: rw via ntfs-3g for another reason is MountedRW with a warning."""
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    fake_runner.on(PROBE, Answer())
    fake_runner.on(MOUNT, Answer(returncode=32))
    fake_runner.on(NTFS3G, Answer())
    fake_runner.on(readback_argv(MEDIABOX_PATH), NOT_MOUNTED, MEDIABOX_FUSE_RW)
    script_desktop_session(fake_runner)
    script_notify(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert (outcome.state, outcome.reason) == (
        VolumeState.MOUNTED_RW,
        "mount exit status 32",
    )
    record = read_record(deck, MEDIABOX_RECORD)
    assert record["reason"] is None
    assert record["warning"] == (
        "MEDIABOX is mounted read-write with ntfs-3g because the kernel driver did"
        " not mount it: mount exit status 32."
    )
    [notify] = argvs_of(fake_runner, SYSTEMD_RUN)
    assert "MEDIABOX is mounted with ntfs-3g" in notify


def test_tool_mapping_keeps_the_openers_mapping_fields(
    ctx, host_tree, tmp_path, fake_runner
):
    """The opener wrote the mapping ahead (DD-10); reconcile adds kname and devnum."""
    runtime_dirs(ctx)
    write_registry(tmp_path, REGISTRY)
    host_tree.add_sysfs_facts(
        facts_text(replace={"/sys/block/dm-0/dm/name": TOOL_MAPPING})
    )
    host_tree.link_by_uuid(PERSONAL_UUID, "sdb1")
    make_mount_base(tmp_path)
    opened = {
        "name": TOOL_MAPPING,
        "kname": None,
        "devnum": None,
        "opened_by": "key-unit",
        "key_unit_invocation_id": "a" * 32,
        "save_pending": True,
    }
    write_record(
        tmp_path,
        PERSONAL_RECORD,
        state="NeedsKey",
        reason="dialog_open",
        mapping=opened,
        mount=None,
    )
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    fake_runner.on(PROBE, Answer())
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_NTFS3_RW)
    script_key_unit(fake_runner, key_unit_show("active", "a" * 32))

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.RELOAD
    )

    assert outcome.state is VolumeState.MOUNTED_RW
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert record["mapping"] == dict(opened, kname="dm-0", devnum="252:0")
    # ADR-0005 D5.2, J001: the key unit opened it, so its save question survives.
    assert [argv[1] for argv in argvs_of(fake_runner, SYSTEMCTL)] == ["show"]


def test_tool_mapping_without_a_record_was_opened_by_the_handler(
    ctx, host_tree, tmp_path, fake_runner
):
    runtime_dirs(ctx)
    write_registry(tmp_path, REGISTRY)
    host_tree.add_sysfs_facts(
        facts_text(replace={"/sys/block/dm-0/dm/name": TOOL_MAPPING})
    )
    host_tree.link_by_uuid(PERSONAL_UUID, "sdb1")
    make_mount_base(tmp_path)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    fake_runner.on(PROBE, Answer())
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_NTFS3_RW)
    script_key_unit(fake_runner)

    reconcile.run(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.START)

    mapping = read_record(tmp_path, PERSONAL_RECORD)["mapping"]
    assert (mapping["opened_by"], mapping["save_pending"]) == ("handler", False)


def test_inner_device_not_listed_yet_records_mount_failed(
    ctx, host_tree, tmp_path, fake_runner
):
    runtime_dirs(ctx)
    write_registry(tmp_path, None)
    known_os_set(tmp_path)
    make_mount_base(tmp_path)
    add_dolphin_sysfs(host_tree, sdc1_holders=("dm-9",))
    script_lsblk(fake_runner, "lsblk-tree-dolphin-unregistered.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_no_session(fake_runner)

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.RELOAD)

    assert (outcome.state, outcome.reason) == (VolumeState.MOUNT_FAILED, "unknown")
    record = read_record(tmp_path, SDC1_RECORD)
    assert record["warning"] == (
        "OBAMA BACKUP 1_2_2025 could not be mounted: the unlocked device dm-9 has"
        " no supported filesystem yet."
    )
    assert argvs_of(fake_runner, MOUNT) == []


def test_inner_device_not_listed_yet_keeps_the_key_units_mapping(
    ctx, host_tree, tmp_path, fake_runner
):
    """A reload between the key unit's open and lsblk listing dm-0 keeps its fields.

    The key unit wrote ``opened_by``, its invocation id and ``save_pending``
    ahead (DD-10); losing them would stop the key unit before its save question
    on the next pass (ADR-0005 D5.2).
    """
    runtime_dirs(ctx)
    write_registry(tmp_path, REGISTRY)
    host_tree.add_sysfs_facts(
        facts_text(replace={"/sys/block/dm-0/dm/name": TOOL_MAPPING})
    )
    host_tree.link_by_uuid(PERSONAL_UUID, "sdb1")
    make_mount_base(tmp_path)
    opened = {
        "name": TOOL_MAPPING,
        "kname": None,
        "devnum": None,
        "opened_by": "key-unit",
        "key_unit_invocation_id": "a" * 32,
        "save_pending": True,
    }
    write_record(
        tmp_path,
        PERSONAL_RECORD,
        state="NeedsKey",
        reason="dialog_open",
        mapping=opened,
        mount=None,
    )
    script_lsblk(fake_runner, "lsblk-tree-personal-locked.json")
    script_key_unit(fake_runner, key_unit_show("active", "a" * 32))
    script_no_session(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.RELOAD
    )

    assert outcome.route.action is Action.MOUNT_INNER_REGISTERED
    assert (outcome.state, outcome.reason) == (VolumeState.MOUNT_FAILED, "unknown")
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert record["mapping"] == opened
    assert argvs_of(fake_runner, MOUNT) == []


def test_inner_device_not_listed_yet_drops_a_mapping_of_another_name(
    ctx, host_tree, tmp_path, fake_runner
):
    runtime_dirs(ctx)
    write_registry(tmp_path, REGISTRY)
    host_tree.add_sysfs_facts(
        facts_text(replace={"/sys/block/dm-0/dm/name": TOOL_MAPPING})
    )
    host_tree.link_by_uuid(PERSONAL_UUID, "sdb1")
    make_mount_base(tmp_path)
    stale = {
        "name": DM0_UDISKS_NAME,
        "kname": "dm-0",
        "devnum": "252:0",
        "opened_by": "other",
        "key_unit_invocation_id": None,
        "save_pending": False,
    }
    write_record(
        tmp_path, PERSONAL_RECORD, state="NotMounted", mapping=stale, mount=None
    )
    script_lsblk(fake_runner, "lsblk-tree-personal-locked.json")
    script_key_unit(fake_runner)
    script_no_session(fake_runner)

    reconcile.run(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.RELOAD)

    assert read_record(tmp_path, PERSONAL_RECORD)["mapping"] is None


# --- UNLOCK_REGISTERED: the stored key (AC-010, AC-014, AC-059, AC-075, DD-18) ---

LOCKED_TREE = Answer.from_fixture("lsblk-tree-personal-locked.json", returncode=0)
NEEDS_KEY_STEP = (
    f"In Desktop Mode, replug the drive or run {CLI} mount --volume PERSONAL. Or"
    f" run {CLI} set-key PERSONAL."
)
START_KEY_UNIT = (SYSTEMCTL, "start", "--no-block", "--", KEY_UNIT)


def open_argv(root: Path) -> tuple[str, ...]:
    """cryptsetup open with the stored key file: a path, never the key."""
    key_file = root / f"var/lib/steamos-mounter/keys/{PERSONAL_UUID}.key"
    return (
        CRYPTSETUP,
        "open",
        "--type",
        "bitlk",
        "--key-file",
        str(key_file),
        "/dev/sdb1",
        TOOL_MAPPING,
    )


@pytest.fixture
def locked(deck):
    """PERSONAL plugged in locked; the returned hook is what cryptsetup open does."""
    return lock_sdb1(deck, TOOL_MAPPING)


@pytest.fixture
def trees(fake_runner) -> None:
    """lsblk shows the locked tree first, then the real tree with dm-0 (ntfs)."""
    fake_runner.on(LSBLK_ARGV, LOCKED_TREE)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")


def script_inner_chain(fake_runner) -> None:
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    fake_runner.on(PROBE, Answer())
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_NTFS3_RW)


def test_stored_key_unlocks_and_mounts_the_inner_device_at_the_fixed_path(
    ctx, deck, fake_runner, locked, trees
):
    """AC-010, AC-059, DD-10: mapping written ahead, one open, mount at the path."""
    write_key_file(deck, PERSONAL_UUID, TEST_KEY)
    ahead = []

    def open_it(command):
        ahead.append(read_record(deck, PERSONAL_RECORD))
        locked(command)

    fake_runner.on(CRYPTSETUP, Answer(), hook=open_it)
    script_inner_chain(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.START
    )

    assert outcome.route.action is Action.UNLOCK_REGISTERED
    assert outcome.state is VolumeState.MOUNTED_RW
    assert argvs_of(fake_runner, CRYPTSETUP) == [open_argv(deck)]
    [call] = [c for c in fake_runner.calls if c.argv[0] == CRYPTSETUP]
    assert (call.has_stdin, call.secret_stdin) == (False, False)
    [before] = ahead
    assert before["state"] == "Mounting"
    assert before["mapping"] == {
        "name": TOOL_MAPPING,
        "kname": None,
        "devnum": None,
        "opened_by": "handler",
        "key_unit_invocation_id": None,
        "save_pending": False,
    }
    record = read_record(deck, PERSONAL_RECORD)
    assert record["mapping"] == dict(before["mapping"], kname="dm-0", devnum="252:0")
    assert (record["mount"]["device"], record["mount"]["target"]) == (
        "/dev/dm-0",
        PERSONAL_PATH,
    )
    assert argvs_of(fake_runner, MOUNT) == [
        (MOUNT, "-i", "-t", "ntfs3", "-o", NTFS_RW_OPTIONS, "/dev/dm-0", PERSONAL_PATH)
    ]
    under_base = {
        item
        for argv in fake_runner.argvs
        for item in argv
        if item.startswith("/run/media/deck/")
    }
    assert under_base == {PERSONAL_PATH}  # AC-059
    assert argvs_of(fake_runner, SYSTEMCTL) == []
    assert argvs_of(fake_runner, LOGINCTL) == []


def test_stored_key_tried_once(ctx, deck, fake_runner, locked, trees, caplog):
    """AC-014: one attempt, NeedsKey, the key unit started instead of a notice."""
    write_key_file(deck, PERSONAL_UUID, TEST_KEY)
    fake_runner.on(CRYPTSETUP, Answer(returncode=2))
    script_desktop_session(fake_runner)
    fake_runner.on(START_KEY_UNIT, Answer())

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.START
    )

    assert outcome.route.action is Action.UNLOCK_REGISTERED
    assert (outcome.state, outcome.reason) == (
        VolumeState.NEEDS_KEY,
        "stored_key_rejected",
    )
    assert argvs_of(fake_runner, CRYPTSETUP) == [open_argv(deck)]
    assert argvs_of(fake_runner, SYSTEMCTL) == [START_KEY_UNIT]
    assert argvs_of(fake_runner, SYSTEMD_RUN) == []  # the dialog replaces it
    assert argvs_of(fake_runner, PROBE) + argvs_of(fake_runner, MOUNT) == []
    record = read_record(deck, PERSONAL_RECORD)
    assert (record["state"], record["reason"], record["mapping"]) == (
        "NeedsKey",
        "stored_key_rejected",
        None,
    )
    assert record["warning"] == "The stored key did not work."
    assert record["next_step"] == NEEDS_KEY_STEP
    logged = outcome_logs(caplog, "NeedsKey")
    assert [r.levelno for r in logged] == [NOTICE, logging.WARNING]
    assert {sm_fields(r)["SM_REASON"] for r in logged} == {"stored_key_rejected"}


def test_no_session_needs_key(ctx, deck, fake_runner, locked, trees, caplog):
    """AC-075: no Desktop Mode session -> no dialog anywhere, "needs a key"."""
    write_key_file(deck, PERSONAL_UUID, TEST_KEY)
    fake_runner.on(CRYPTSETUP, Answer(returncode=2))
    script_no_session(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.START
    )

    assert (outcome.state, outcome.reason) == (VolumeState.NEEDS_KEY, "no_session")
    assert len(argvs_of(fake_runner, CRYPTSETUP)) == 1
    assert argvs_of(fake_runner, SYSTEMCTL) == []
    assert argvs_of(fake_runner, SYSTEMD_RUN) == []
    record = read_record(deck, PERSONAL_RECORD)
    assert (record["state"], record["reason"]) == ("NeedsKey", "no_session")
    assert record["warning"] == (
        "The stored key did not work, and there was no Desktop Mode session for"
        " the key dialog."
    )
    assert record["next_step"] == NEEDS_KEY_STEP
    assert state.words(VolumeState.NEEDS_KEY, record["reason"]) == "needs a key"
    notices = outcome_logs(caplog, "NeedsKey")
    assert [sm_fields(r)["SM_REASON"] for r in notices if r.levelno == NOTICE] == [
        "no_session"
    ]


def test_unsure_session_needs_key_without_a_dialog(
    ctx, deck, fake_runner, locked, trees
):
    """AC-076: a failed logind query is "not sure": no key unit, no notice."""
    make_keys_dir(deck)
    fake_runner.on((LOGINCTL, "show-user"), Answer(returncode=1))

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.START
    )

    assert (outcome.state, outcome.reason) == (
        VolumeState.NEEDS_KEY,
        "session_not_sure",
    )
    assert argvs_of(fake_runner, CRYPTSETUP) == []  # no key file: nothing to try
    assert argvs_of(fake_runner, SYSTEMCTL) == []
    assert read_record(deck, PERSONAL_RECORD)["warning"] == (
        "There is no stored key, and the Desktop Mode session could not be"
        " confirmed for the key dialog."
    )


def test_reload_never_starts_the_key_unit(ctx, deck, fake_runner, locked, trees):
    """ADR-0005 D1.3: a reload keeps the stored-key reason; no session check."""
    make_keys_dir(deck)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.RELOAD
    )

    assert (outcome.state, outcome.reason) == (
        VolumeState.NEEDS_KEY,
        "stored_key_missing",
    )
    assert argvs_of(fake_runner, LOGINCTL) == []
    assert argvs_of(fake_runner, SYSTEMCTL) == []
    record = read_record(deck, PERSONAL_RECORD)
    assert (record["trigger"], record["warning"]) == (
        "reload",
        "There is no stored key.",
    )


def test_fresh_cli_request_starts_the_key_unit_for_a_missing_key(
    ctx, deck, fake_runner, locked, trees
):
    """D014: ``mount --volume`` in Desktop Mode starts the key unit (AC-075)."""
    make_keys_dir(deck)
    write_record(
        deck,
        PERSONAL_RECORD,
        state="NeedsKey",
        reason="no_session",
        mapping=None,
        mount=None,
        cli_request={"token": "0123456789abcdef", "at": timestamp(ctx, 5)},
    )
    script_desktop_session(fake_runner)
    fake_runner.on(START_KEY_UNIT, Answer())

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.RELOAD
    )

    assert (outcome.state, outcome.reason) == (
        VolumeState.NEEDS_KEY,
        "stored_key_missing",
    )
    assert argvs_of(fake_runner, SYSTEMCTL) == [START_KEY_UNIT]
    record = read_record(deck, PERSONAL_RECORD)
    assert (record["trigger"], record["cli_request"]) == ("cli", None)
    assert record["warning"] == "There is no stored key."


def test_key_unit_that_does_not_start_is_logged(
    ctx, deck, fake_runner, locked, trees, caplog
):
    make_keys_dir(deck)
    script_desktop_session(fake_runner)
    fake_runner.on(START_KEY_UNIT, Answer(returncode=1, stderr=b"start limit hit"))

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.START
    )

    assert outcome.reason == "stored_key_missing"
    assert any(
        r.levelno == logging.WARNING
        and "did not start" in r.getMessage()
        and "start limit hit" in r.getMessage()
        for r in caplog.records
    )


def test_bad_key_permissions_need_a_key_and_notify(
    ctx, deck, fake_runner, locked, trees
):
    """DD-18, DD-19: no attempt, no dialog, a notification pointing to doctor."""
    key_file = write_key_file(deck, PERSONAL_UUID, TEST_KEY, mode=0o644)
    script_desktop_session(fake_runner)
    script_notify(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.START
    )

    assert (outcome.state, outcome.reason) == (
        VolumeState.NEEDS_KEY,
        "key_permissions",
    )
    assert argvs_of(fake_runner, CRYPTSETUP) == []
    assert argvs_of(fake_runner, SYSTEMCTL) == []
    record = read_record(deck, PERSONAL_RECORD)
    assert record["next_step"] == f"Run {CLI} doctor, then {CLI} set-key PERSONAL."
    [notify] = argvs_of(fake_runner, SYSTEMD_RUN)
    assert "PERSONAL needs a key" in notify
    assert notify[-1].endswith(f"Run {CLI} doctor, then {CLI} set-key PERSONAL.")
    assert key_file.read_bytes() == TEST_KEY
    assert oct(key_file.stat().st_mode & 0o777) == oct(0o644)


def test_cryptsetup_failure_is_mount_failed_without_a_dialog(
    ctx, deck, fake_runner, locked, trees
):
    """Not a rejected key (exit 5 busy): the key may be right, so no key unit."""
    write_key_file(deck, PERSONAL_UUID, TEST_KEY)
    fake_runner.on(CRYPTSETUP, Answer(returncode=5, stderr=b"Device busy."))
    script_no_session(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.START
    )

    assert (outcome.state, outcome.reason) == (VolumeState.MOUNT_FAILED, "unknown")
    assert len(argvs_of(fake_runner, CRYPTSETUP)) == 1
    assert argvs_of(fake_runner, SYSTEMCTL) == []
    record = read_record(deck, PERSONAL_RECORD)
    assert (record["mapping"], record["warning"]) == (
        None,
        "PERSONAL could not be unlocked with its stored key: cryptsetup failed.",
    )


def test_unlock_mounts_on_a_cli_request_despite_an_old_user_unmount(
    ctx, deck, fake_runner, locked, trees
):
    """D014, DD-11: the CLI marker survives the write-ahead; a new mapping mounts."""
    write_key_file(deck, PERSONAL_UUID, TEST_KEY)
    write_record(
        deck,
        PERSONAL_RECORD,
        state="UnmountedByUser",
        mapping=None,
        mount=None,
        unmounted_by_user={"devnum": "252:0", "at": timestamp(ctx, 600)},
        cli_request={"token": "0123456789abcdef", "at": timestamp(ctx, 5)},
    )
    fake_runner.on(CRYPTSETUP, Answer(), hook=locked)
    script_inner_chain(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.RELOAD
    )

    assert outcome.state is VolumeState.MOUNTED_RW
    record = read_record(deck, PERSONAL_RECORD)
    assert (record["trigger"], record["cli_request"], record["unmounted_by_user"]) == (
        "cli",
        None,
        None,
    )


@pytest.mark.parametrize("holder", [True, False], ids=["dm-0-listed", "no-holder"])
def test_inner_filesystem_never_ready_keeps_the_open_mapping(
    ctx, deck, fake_runner, fake_clock, locked, holder
):
    """DD-29: 5 s without an inner type -> MountFailed; teardown still closes it."""
    write_key_file(deck, PERSONAL_UUID, TEST_KEY)
    fake_runner.on(CRYPTSETUP, Answer(), hook=locked if holder else None)
    fake_runner.on(
        LSBLK_ARGV,
        LOCKED_TREE,
        hook=lambda _command: fake_clock.advance(3),
        repeat=True,
    )
    script_no_session(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.START
    )

    kname = "dm-0" if holder else "-"
    assert (outcome.state, outcome.reason) == (VolumeState.MOUNT_FAILED, "unknown")
    record = read_record(deck, PERSONAL_RECORD)
    assert record["warning"] == (
        f"PERSONAL could not be mounted: the unlocked device {kname} has no"
        " supported filesystem yet."
    )
    assert record["mapping"]["name"] == TOOL_MAPPING
    assert record["mapping"]["kname"] == ("dm-0" if holder else None)
    assert argvs_of(fake_runner, MOUNT) == []


@pytest.mark.parametrize(
    ("handler", "action"),
    [
        (reconcile_unlock.unlock, Action.UNLOCK_REGISTERED),
        (reconcile_unlock.mount_inner_registered, Action.MOUNT_INNER_REGISTERED),
    ],
    ids=["unlock", "mount-inner"],
)
def test_registered_bitlocker_route_without_an_entry_is_refused(
    ctx, fake_runner, handler, action
):
    """Routing always names the entry; a route without one runs nothing."""
    current = reconcile_report.PassState(
        ctx=ctx,
        kind=InstanceKind.REGISTERED,
        device_path=PERSONAL_DEVICE,
        trigger=Trigger.START,
        deadline=60.0,
    )

    with pytest.raises(ValueError, match="without a registry entry"):
        handler(current, None, Route(action, "registered"))
    assert fake_runner.argvs == []


# --- the key unit interplay (ADR-0005 D5.2, J001) ---------------------------------


def key_unit_record(**mapping) -> Record:
    values = {
        "name": TOOL_MAPPING,
        "kname": "dm-0",
        "devnum": "252:0",
        "opened_by": "key-unit",
        "key_unit_invocation_id": KEY_UNIT_ID,
        "save_pending": True,
    }
    values.update(mapping)
    return Record.from_dict(builders.record_dict(mapping=values))


def test_key_unit_keeps_running_after_its_own_unlock():
    record = key_unit_record()

    assert not reconcile_unlock.key_unit_must_stop(TOOL_MAPPING, record, KEY_UNIT_ID)


@pytest.mark.parametrize(
    ("mapping_name", "record", "invocation_id"),
    [
        (DM0_UDISKS_NAME, key_unit_record(), KEY_UNIT_ID),
        (None, key_unit_record(), KEY_UNIT_ID),
        (TOOL_MAPPING, None, KEY_UNIT_ID),
        (TOOL_MAPPING, key_unit_record(opened_by="handler"), KEY_UNIT_ID),
        (TOOL_MAPPING, key_unit_record(), "c" * 32),
        (TOOL_MAPPING, key_unit_record(), ""),
        (TOOL_MAPPING, key_unit_record(name=f"{TOOL_MAPPING}0"), KEY_UNIT_ID),
        (
            TOOL_MAPPING,
            Record.from_dict(builders.record_dict(mapping=None)),
            KEY_UNIT_ID,
        ),
    ],
    ids=[
        "foreign-name",
        "no-name",
        "no-record",
        "opened-by-handler",
        "other-invocation",
        "no-invocation",
        "other-mapping",
        "no-mapping",
    ],
)
def test_key_unit_is_stopped_when_it_did_not_open_the_mapping(
    mapping_name, record, invocation_id
):
    assert reconcile_unlock.key_unit_must_stop(mapping_name, record, invocation_id)


def test_key_unit_name_is_the_registered_instance():
    assert reconcile_unlock.key_unit_name(PERSONAL_DEVICE) == KEY_UNIT


def dialog_open_record(root: Path) -> None:
    """What the key unit leaves while its password dialog is open."""
    write_record(
        root,
        PERSONAL_RECORD,
        state="NeedsKey",
        reason="dialog_open",
        mapping=None,
        mount=None,
    )


def test_dolphin_unlock_stops_the_active_key_unit(ctx, deck, fake_runner, caplog):
    """ADR-0005 D5.2: a foreign mapping closes the dialog, then mounts as usual."""
    dialog_open_record(deck)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    script_key_unit(fake_runner, key_unit_show("active", KEY_UNIT_ID))
    fake_runner.on((SYSTEMCTL, "stop"), Answer())
    script_inner_chain(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.RELOAD
    )

    assert outcome.state is VolumeState.MOUNTED_RW
    systemctl = argvs_of(fake_runner, SYSTEMCTL)
    assert systemctl == [
        (
            SYSTEMCTL,
            "show",
            "--property=LoadState,ActiveState,InvocationID",
            "--",
            KEY_UNIT,
        ),
        (SYSTEMCTL, "stop", "--no-block", "--", KEY_UNIT),
    ]
    order = [argv[0] for argv in fake_runner.argvs]
    assert order.index(SYSTEMCTL) < order.index(PROBE)
    assert any(
        r.levelno == NOTICE and "unlocked another way" in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.parametrize(
    "answer",
    [
        key_unit_show("inactive"),
        key_unit_show("deactivating", KEY_UNIT_ID),
        Answer(stdout=b"LoadState=not-found\nActiveState=inactive\n"),
    ],
    ids=["inactive", "deactivating", "not-found"],
)
def test_key_unit_that_is_not_running_is_left_alone(ctx, deck, fake_runner, answer):
    dialog_open_record(deck)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    script_key_unit(fake_runner, answer)
    script_inner_chain(fake_runner)

    reconcile.run(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.RELOAD)

    assert [argv[1] for argv in argvs_of(fake_runner, SYSTEMCTL)] == ["show"]


def test_key_unit_query_failure_still_mounts(ctx, deck, fake_runner, caplog):
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    script_key_unit(fake_runner, Answer(returncode=1, stderr=b"bus error"))
    script_inner_chain(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.RELOAD
    )

    assert outcome.state is VolumeState.MOUNTED_RW
    assert any(
        r.levelno == logging.WARNING and "cannot tell whether" in r.getMessage()
        for r in caplog.records
    )


def test_failed_key_unit_stop_is_a_warning(ctx, deck, fake_runner, caplog):
    dialog_open_record(deck)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    script_key_unit(fake_runner, key_unit_show("active", KEY_UNIT_ID))
    fake_runner.on((SYSTEMCTL, "stop"), Answer(returncode=1))
    script_inner_chain(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, Trigger.RELOAD
    )

    assert outcome.state is VolumeState.MOUNTED_RW
    assert any(
        r.levelno == logging.WARNING and "unlocked another way" in r.getMessage()
        for r in caplog.records
    )


# --- errors: the top-level catch (Required Specific Tests 9) --------------------


def boom(_command):
    raise RuntimeError("simulated failure")


def test_internal_error_is_recorded_and_the_pass_returns(
    ctx, deck, fake_runner, caplog
):
    """Exit-0 discipline: the error is recorded; the write-ahead target survives."""
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    fake_runner.on(PROBE, Answer(), hook=boom)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert (outcome.state, outcome.reason) == (
        VolumeState.MOUNT_FAILED,
        "internal_error",
    )
    assert outcome.route.action is Action.MOUNT_REGISTERED
    record = read_record(deck, MEDIABOX_RECORD)
    assert (record["state"], record["reason"]) == ("MountFailed", "internal_error")
    assert (
        record["next_step"]
        == f"See the journal, then run {CLI} mount --volume MEDIABOX."
    )
    assert (record["mount"]["status"], record["mount"]["target"]) == (
        "pending",
        MEDIABOX_PATH,
    )
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert errors[-1].exc_info is not None


def test_read_back_failure_is_recorded_as_probe_failed(ctx, deck, fake_runner):
    """mounter raises ToolError when findmnt itself fails (IP-05)."""
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    fake_runner.on(PROBE, Answer())
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback_argv(MEDIABOX_PATH), Answer(returncode=2))

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert (outcome.state, outcome.reason) == (VolumeState.MOUNT_FAILED, "probe_failed")
    record = read_record(deck, MEDIABOX_RECORD)
    assert record["mount"]["status"] == "pending"


def test_lsblk_failure_updates_an_existing_registered_record(ctx, deck, fake_runner):
    """IP-04: lsblk failing is MountFailed probe_failed when a record exists."""
    write_record(deck, MEDIABOX_RECORD, **mediabox_record())
    fake_runner.on(LSBLK_ARGV, Answer(returncode=1, stderr=b"lsblk: broken\n"))

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert outcome.route.action is Action.FAIL_CLOSED
    assert (outcome.state, outcome.reason) == (VolumeState.MOUNT_FAILED, "probe_failed")
    record = read_record(deck, MEDIABOX_RECORD)
    assert (record["state"], record["reason"]) == ("MountFailed", "probe_failed")
    assert record["mount"]["status"] == "mounted"  # the mount facts are kept


@pytest.mark.parametrize(
    ("kind", "device_path"),
    [
        (InstanceKind.REGISTERED, MEDIABOX_DEVICE),
        (InstanceKind.AUTO, SDB5_SYSPATH),
    ],
)
def test_lsblk_failure_without_a_record_writes_nothing(
    ctx, deck, fake_runner, caplog, kind, device_path
):
    fake_runner.on(LSBLK_ARGV, Answer(returncode=1))

    outcome = reconcile.run(ctx, kind, device_path, Trigger.START)

    assert (outcome.state, outcome.reason) == (None, "probe_failed")
    for sub in ("registered", "auto"):
        assert os.listdir(deck / "run/steamos-mounter/records" / sub) == []
    assert any(r.levelno == logging.ERROR for r in caplog.records)


def test_registered_path_that_is_no_record_key_records_nothing(
    ctx, deck, fake_runner, host_tree
):
    """The top-level catch writes only to a record key it can trust."""
    host_tree.link_by_uuid("_odd", "sdb5")
    fake_runner.on(LSBLK_ARGV, Answer(returncode=1))

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, "/dev/disk/by-uuid/_odd", Trigger.START
    )

    assert (outcome.state, outcome.reason) == (None, "probe_failed")
    assert os.listdir(deck / "run/steamos-mounter/records/registered") == []


def test_error_after_the_final_record_keeps_it(ctx, deck, fake_runner, fake_kmsg):
    """A failure while notifying does not turn a mounted volume into MountFailed."""
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE)
    script_dirty_mediabox(fake_runner, fake_kmsg)
    fake_runner.on((LOGINCTL, "show-user"), Answer(), hook=boom)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert outcome.state is VolumeState.MOUNTED_RW_DIRTY
    assert read_record(deck, MEDIABOX_RECORD)["state"] == "MountedRWDirty"


def test_volume_lock_held_past_the_deadline_is_logged_only(
    ctx, deck, fake_runner, fake_clock, caplog
):
    lock = os.open(deck / MEDIABOX_LOCK, os.O_RDWR | os.O_CREAT)
    fcntl.flock(lock, fcntl.LOCK_EX)
    fake_runner.on(
        LSBLK_ARGV,
        Answer.from_fixture("lsblk-columns-tree.json"),
        hook=lambda _c: fake_clock.advance(59.9),
    )
    try:
        outcome = reconcile.run(
            ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
        )
    finally:
        os.close(lock)

    assert outcome.state is None
    assert outcome.route.action is Action.MOUNT_REGISTERED
    assert not (deck / MEDIABOX_RECORD).exists()
    assert any("could not be recorded" in r.getMessage() for r in caplog.records)


def test_every_action_has_a_handler():
    assert set(reconcile.ACTION_HANDLERS) == set(Action)


@pytest.mark.parametrize(
    ("volume_state", "reason"),
    [
        (VolumeState.MOUNT_FAILED, reconcile.REASON_INTERNAL),
        (VolumeState.MOUNT_FAILED, reconcile.REASON_PROBE_FAILED),
        (VolumeState.MOUNT_FAILED, reconcile_mount.REASON_UNKNOWN),
        (VolumeState.MOUNT_FAILED, reconcile_mount.REASON_DEVICE_BUSY),
        (VolumeState.MOUNT_FAILED, reconcile_mount.REASON_NO_FREE_NAME),
        (VolumeState.MOUNTED_ELSEWHERE, reconcile_mount.REASON_HELD),
        (VolumeState.NOT_MOUNTED, reconcile.NO_PARTITION_INSTANCE),
    ],
)
def test_every_recorded_reason_is_a_known_code(volume_state, reason):
    """Records keep only ``state.KNOWN_REASONS`` codes; free text goes to warnings."""
    assert reason in state.KNOWN_REASONS[volume_state]


# --- the notification's time budget (TimeoutStartSec=90) ------------------------

MEDIABOX_AS_EXFAT = builders.registry_text(
    [builders.RegistryVolume("MEDIABOX", MEDIABOX_UUID, MEDIABOX_PATH, "exfat")]
)
NO_TIME_LEFT = "notification not sent: no time left before the unit's start timeout"


def refused_mediabox(deck, fake_runner, fake_clock, *, spent: float) -> None:
    """MEDIABOX registered as exFAT (MountFailed, notified); lsblk takes ``spent`` s."""
    write_registry(deck, MEDIABOX_AS_EXFAT)
    fake_runner.on(
        LSBLK_ARGV,
        Answer.from_fixture("lsblk-columns-tree.json", returncode=0),
        hook=lambda _c: fake_clock.advance(spent),
    )


def notify_timeouts(fake_runner) -> list[tuple[str, float]]:
    return [
        (call.argv[1], call.timeout)
        for call in fake_runner.calls
        if call.argv[0] in {LOGINCTL, SYSTEMD_RUN}
    ]


def notify_warnings(caplog) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and sm_fields(r).get("SM_EVENT") == "notify"
    ]


def test_notification_with_time_to_spare_keeps_each_steps_timeout(
    ctx, deck, fake_runner, fake_clock, caplog
):
    refused_mediabox(deck, fake_runner, fake_clock, spent=0.0)
    script_desktop_session(fake_runner)
    script_notify(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert outcome.state is VolumeState.MOUNT_FAILED
    assert notify_timeouts(fake_runner) == [
        ("show-user", 10.0),
        ("show-seat", 10.0),
        ("show-session", 10.0),
        ("--user", 15.0),
    ]
    assert notify_warnings(caplog) == []


def test_notification_steps_share_what_is_left_of_80_s(
    ctx, deck, fake_runner, fake_clock, caplog
):
    """72 s spent: 8 s are left before the 80 s mark, for every step."""
    refused_mediabox(deck, fake_runner, fake_clock, spent=72.0)
    script_desktop_session(fake_runner)
    script_notify(fake_runner)

    reconcile.run(ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START)

    assert notify_timeouts(fake_runner) == [
        ("show-user", 8.0),
        ("show-seat", 8.0),
        ("show-session", 8.0),
        ("--user", 8.0),
    ]


def test_budget_gone_before_the_session_lookup_skips_with_a_warning(
    ctx, deck, fake_runner, fake_clock, caplog
):
    refused_mediabox(deck, fake_runner, fake_clock, spent=80.0)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert (outcome.state, outcome.reason) == (
        VolumeState.MOUNT_FAILED,
        "fstype_mismatch",
    )
    assert read_record(deck, MEDIABOX_RECORD)["state"] == "MountFailed"
    assert notify_timeouts(fake_runner) == []
    assert notify_warnings(caplog) == [NO_TIME_LEFT]


def test_budget_gone_during_the_session_lookup_skips_with_a_warning(
    ctx, deck, fake_runner, fake_clock, caplog
):
    refused_mediabox(deck, fake_runner, fake_clock, spent=75.0)
    fake_runner.on(
        (LOGINCTL, "show-user"),
        "loginctl-user-deck.txt",
        hook=lambda _c: fake_clock.advance(5),
    )

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert outcome.state is VolumeState.MOUNT_FAILED
    assert notify_timeouts(fake_runner) == [("show-user", 5.0)]
    assert notify_warnings(caplog) == [NO_TIME_LEFT]


def test_budget_gone_between_the_session_lookup_and_the_send_skips_with_a_warning(
    ctx, deck, fake_runner, fake_clock, caplog
):
    refused_mediabox(deck, fake_runner, fake_clock, spent=70.0)
    fake_runner.on(
        (LOGINCTL, "show-session"),
        "loginctl-session-5-properties.txt",
        hook=lambda _c: fake_clock.advance(10),
    )
    script_desktop_session(fake_runner)

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE, Trigger.START
    )

    assert outcome.state is VolumeState.MOUNT_FAILED
    assert argvs_of(fake_runner, SYSTEMD_RUN) == []
    assert [verb for verb, _ in notify_timeouts(fake_runner)] == [
        "show-user",
        "show-seat",
        "show-session",
    ]
    assert notify_warnings(caplog) == [NO_TIME_LEFT]


def test_every_command_hanging_to_its_timeout_still_ends_by_80_s(
    ctx, host_tree, tmp_path, fake_runner, fake_clock, caplog
):
    """The worst case: each call takes its whole timeout, the handler ends by 80 s.

    Without the budget: lsblk 10 + findmnt 10 + mount 30 + read-back 10 + three
    loginctl 30 + systemd-run 15 = 105 s, past TimeoutStartSec=90.
    """

    def hangs(command) -> None:
        fake_clock.advance(command.timeout)

    fake_runner.on(
        LSBLK_ARGV,
        Answer.from_fixture("lsblk-tree-with-exfat-sdc1.json", returncode=0),
        hook=hangs,
        repeat=True,
    )
    exfat_world(ctx, host_tree, tmp_path, fake_runner)
    fake_runner.on(TABLE_ARGV, REAL_TABLE, hook=hangs)
    fake_runner.on(MOUNT, Answer(returncode=32), hook=hangs)
    fake_runner.on(readback_argv(GAMES_PATH), NOT_MOUNTED, hook=hangs)
    fake_runner.on((LOGINCTL, "show-user"), "loginctl-user-deck.txt", hook=hangs)
    fake_runner.on(
        (LOGINCTL, "show-seat"), "loginctl-seat-seat0-active.txt", hook=hangs
    )
    fake_runner.on(
        (LOGINCTL, "show-session"), "loginctl-session-5-properties.txt", hook=hangs
    )
    fake_runner.on((SYSTEMD_RUN, "--user"), Answer(), hook=hangs)
    start = fake_clock.monotonic()

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.START)

    assert outcome.state is VolumeState.MOUNT_FAILED
    assert fake_clock.monotonic() - start <= 80.0  # 10 s inside TimeoutStartSec=90
    assert argvs_of(fake_runner, SYSTEMD_RUN) == []
    assert notify_warnings(caplog) == [NO_TIME_LEFT]


# --- module shape -----------------------------------------------------------------


def test_public_names():
    assert reconcile.HANDLER_DEADLINE == 60.0
    assert reconcile.ReconcileOutcome is reconcile_report.ReconcileOutcome
    assert reconcile.CLI_REQUEST_WINDOW == 120.0


@pytest.mark.parametrize(
    "module", [reconcile, reconcile_mount, reconcile_report, reconcile_unlock]
)
def test_module_stays_under_500_lines(module):
    assert len(Path(module.__file__).read_text().splitlines()) < 500
