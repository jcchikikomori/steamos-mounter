"""teardown: the ExecStop= and ExecStopPost= routine, on fakes.

Design Doc "Teardown" (flowchart, items 1 to 5), "Unplug Teardown",
"BitLocker Unlock and Mappings" (DD-15), "Locks" (I007), "Runtime State
Records" and the EARS block "Records and Teardown"; ADR-0001 Decision 3 and
guidance 8 to 10, ADR-0004 D5. Every command goes through the fake runner;
sysfs, ``/dev/disk/by-uuid``, the registry, records, locks and the mount
directories are real files under ``tmp_path``.
"""

import fcntl
import json
import logging
import os

import pytest

from steamos_mounter import teardown
from steamos_mounter.escape import escape_path, unit_name
from steamos_mounter.journal import NOTICE
from steamos_mounter.locks import LockTimeout
from steamos_mounter.model import InstanceKind
from steamos_mounter.mounter import UnmountResult
from steamos_mounter.platforms.steamos import TOOLS
from steamos_mounter.routing import AUTO_TEMPLATE
from steamos_mounter.teardown import ServiceResult, TeardownReport
from tests.helpers import builders
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture
from tests.helpers.flows import (
    CRYPTSETUP,
    DMSETUP,
    TABLE_ARGV,
    make_leaf,
    read_record,
    readback_argv,
    runtime_dirs,
    sm_fields,
    write_record,
    write_registry,
)
from tests.helpers.host_tree import SysfsDevice

UMOUNT = TOOLS.umount
FINDMNT = TOOLS.findmnt
CLI = "sudo /opt/steamos-mounter/bin/steamos-mounter"
PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
PERSONAL_DEVICE = f"/dev/disk/by-uuid/{PERSONAL_UUID}"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
PERSONAL_RECORD = f"run/steamos-mounter/records/registered/{PERSONAL_UUID}.json"
PERSONAL_LOCK = f"run/steamos-mounter/locks/volume-{PERSONAL_UUID}.lock"
TOOL_MAPPING = f"steamos-mounter-{PERSONAL_UUID}"
DOLPHIN_NAME = "PAT4T4SHUAWEI_PERSONAL_4_3_2024"
REGISTERED_UNIT = (
    "steamos-mounter@dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52"
    "\\x2da297\\x2d31643c64724d.service"
)
SDB1_SYSPATH = "/sys/devices/host-tree/block/sdb/sdb1"
GAMES_PATH = "/run/media/deck/GAMES"
GAMES_UUID = "1234-ABCD"
SDC1_SYSPATH = (
    "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-2/2-2:1.0/host1/"
    "target1:0:0/1:0:0:0/block/sdc/sdc1"
)
SDC1_RECORD = "run/steamos-mounter/records/auto/sdc1-8_33.json"
AUTO_UNIT = unit_name(AUTO_TEMPLATE, escape_path(SDC1_SYSPATH))
NOW = "2026-10-08T02:11:40Z"  # FakeClock's default start
TEARDOWN_LOGGERS = "steamos_mounter.teardown"  # teardown and teardown_report

UNPLUG_UMOUNT = (UMOUNT, "-l", PERSONAL_PATH)
NORMAL_UMOUNT = (UMOUNT, PERSONAL_PATH)
DEPS_DM0 = (DMSETUP, "deps", "-o", "devno", "-j", "252", "-m", "0")
DEPS_DM1 = (DMSETUP, "deps", "-o", "devno", "-j", "252", "-m", "1")
CLOSE_OWN = (CRYPTSETUP, "close", TOOL_MAPPING)
CLOSE_OWN_DEFERRED = (CRYPTSETUP, "close", "--deferred", TOOL_MAPPING)
REMOVE_DM1 = (DMSETUP, "remove", "--deferred", "-j", "252", "-m", "1")
REMOVE_DM0 = (DMSETUP, "remove", "--deferred", "-j", "252", "-m", "0")

DEPS_ON_SDB1 = Answer.from_fixture("dmsetup-deps-devno.txt", returncode=0)
PERSONAL_MOUNTED = Answer.from_fixture("findmnt-personal-ntfs3-rw.json", returncode=0)
GAMES_MOUNTED = Answer.from_fixture("findmnt-games-exfat-rw.json", returncode=0)
NOT_MOUNTED = Answer.from_fixture("findmnt-sdb5-not-mounted.json")
BUSY = Answer(
    returncode=32, stderr=b"umount: /run/media/deck/PERSONAL: target is busy.\n"
)

OWN_MAPPING = {
    "name": TOOL_MAPPING,
    "kname": "dm-0",
    "devnum": "252:0",
    "opened_by": "handler",
    "key_unit_invocation_id": None,
    "save_pending": False,
}
DOLPHIN_MAPPING = dict(
    OWN_MAPPING, name=DOLPHIN_NAME, kname="dm-1", devnum="252:1", opened_by="other"
)
OWN_DM = SysfsDevice(kname="dm-0", devnum="252:0", dm_name=TOOL_MAPPING)
DOLPHIN_DM = SysfsDevice(kname="dm-1", devnum="252:1", dm_name=DOLPHIN_NAME)


PERSONAL_MOUNT = {
    "status": "mounted",
    "target": PERSONAL_PATH,
    "device": "/dev/dm-0",
    "devnum": "252:0",
    "driver": "ntfs3",
    "mode": "rw",
    "created_dir": True,
}
SDC1_SOURCE = {"kname": "sdc1", "devnum": "8:33", "syspath": SDC1_SYSPATH}


def personal_record(**changes) -> bytes:
    """PERSONAL mounted at its fixed path from the tool's mapping on sdb1."""
    fields = {
        "state": "MountedRW",
        "reason": None,
        "warning": None,
        "next_step": "-",
        "unit": REGISTERED_UNIT,
        "source": {"kname": "sdb1", "devnum": "8:17", "syspath": SDB1_SYSPATH},
        "mapping": dict(OWN_MAPPING),
        "mount": dict(PERSONAL_MOUNT),
    }
    return json.dumps(builders.record_dict(**(fields | changes))).encode()


def games_record(**changes) -> bytes:
    """The auto record test_flow_unregistered_exfat leaves for GAMES on sdc1."""
    fields = {
        "kind": "auto",
        "key": "sdc1-8_33",
        "name": "GAMES",
        "unit": AUTO_UNIT,
        "state": "MountedRW",
        "reason": None,
        "warning": None,
        "next_step": "-",
        "source": dict(SDC1_SOURCE),
        "mapping": None,
        "mount": {
            "status": "mounted",
            "target": GAMES_PATH,
            "device": "/dev/sdc1",
            "devnum": "8:33",
            "driver": "exfat",
            "mode": "rw",
            "created_dir": True,
        },
        "attempt": {"probe": None, "steps": [], "skipped": []},
    }
    return json.dumps(builders.record_dict(**(fields | changes))).encode()


def plug_sdb1(host_tree) -> None:
    host_tree.add_block(SysfsDevice(kname="sdb", devnum="8:16"))
    host_tree.add_block(SysfsDevice(kname="sdb1", devnum="8:17", parent="sdb"))


def plug_sdc1(host_tree) -> None:
    host_tree.add_block(SysfsDevice(kname="sdc", devnum="8:32"))
    host_tree.add_block(
        SysfsDevice(kname="sdc1", devnum="8:33", parent="sdc", syspath=SDC1_SYSPATH)
    )


def own_messages(caplog) -> list[str]:
    return [
        item.getMessage()
        for item in caplog.records
        if item.name.startswith(TEARDOWN_LOGGERS)
    ]


def timeouts(fake_runner) -> list[float]:
    return [call.timeout for call in fake_runner.calls]


def table_with_games() -> Answer:
    document = json.loads(load_fixture("findmnt-real-list.json"))
    document["filesystems"].extend(
        json.loads(load_fixture("findmnt-games-exfat-rw.json"))["filesystems"]
    )
    return Answer(stdout=json.dumps(document).encode(), returncode=0)


@pytest.fixture
def personal(ctx, tmp_path):
    """The runtime tree and PERSONAL's empty leaf directory (created_dir true)."""
    runtime_dirs(ctx)
    return make_leaf(tmp_path, PERSONAL_PATH)


# --- unplug (AC-031, DD-15) -------------------------------------------------------


def test_unplug_lazy_and_deferred(
    ctx, tmp_path, host_tree, fake_runner, personal, no_holders
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record())
    host_tree.add_block(OWN_DM)
    host_tree.add_block(DOLPHIN_DM)
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED)
    fake_runner.on(UNPLUG_UMOUNT, Answer())
    fake_runner.on(DEPS_DM0, DEPS_ON_SDB1)
    fake_runner.on(DEPS_DM1, DEPS_ON_SDB1)
    fake_runner.on(CLOSE_OWN_DEFERRED, Answer())
    fake_runner.on(REMOVE_DM1, Answer())

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report == TeardownReport(
        unplugged=True,
        unmounts=(UnmountResult(PERSONAL_PATH, "lazy", ""),),
        closes=(TOOL_MAPPING, DOLPHIN_NAME),
        busy=(),
    )
    assert fake_runner.argvs == [
        readback_argv(PERSONAL_PATH),
        UNPLUG_UMOUNT,
        DEPS_DM0,
        DEPS_DM1,
        CLOSE_OWN_DEFERRED,
        REMOVE_DM1,
    ]
    assert timeouts(fake_runner) == [10.0] * 6
    assert not any(DOLPHIN_NAME in item for argv in fake_runner.argvs for item in argv)
    assert not personal.exists()
    assert personal.parent.is_dir()
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert record["state"] == "NotPresent"
    assert record["reason"] is None
    assert record["next_step"] == "Plug the drive in."
    assert record["mount"]["status"] == "unmounted"
    assert record["mapping"] is None
    assert record["busy"] == []
    assert record["service"]["result"] is None


def test_unplug_second_call_runs_nothing(
    ctx, tmp_path, host_tree, fake_runner, personal, no_holders
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record())
    host_tree.add_block(OWN_DM)
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED)
    fake_runner.on(UNPLUG_UMOUNT, Answer())
    fake_runner.on(DEPS_DM0, DEPS_ON_SDB1)
    fake_runner.on(CLOSE_OWN_DEFERRED, Answer())
    teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)
    calls = len(fake_runner.calls)

    again = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert again == TeardownReport(unplugged=True, unmounts=(), closes=(), busy=())
    assert len(fake_runner.calls) == calls
    assert read_record(tmp_path, PERSONAL_RECORD)["state"] == "NotPresent"


def test_unplug_failures_are_busy_and_the_sweep_tries_again(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record())
    host_tree.add_block(OWN_DM)
    host_tree.add_block(DOLPHIN_DM)
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED)
    fake_runner.on(UNPLUG_UMOUNT, Answer())
    fake_runner.on(DEPS_DM0, DEPS_ON_SDB1, repeat=True)
    fake_runner.on(DEPS_DM1, DEPS_ON_SDB1, repeat=True)
    fake_runner.on(CLOSE_OWN_DEFERRED, Answer(returncode=1), Answer())
    fake_runner.on(REMOVE_DM1, Answer(returncode=1), Answer())

    first = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)
    kept = read_record(tmp_path, PERSONAL_RECORD)
    second = teardown.sweep(
        ctx,
        InstanceKind.REGISTERED,
        PERSONAL_DEVICE,
        ServiceResult(result="success", exit_code="exited", exit_status="0"),
    )

    assert first.closes == ()
    assert first.busy == (TOOL_MAPPING, DOLPHIN_NAME)
    assert kept["busy"] == [TOOL_MAPPING, DOLPHIN_NAME]
    assert kept["mapping"] == OWN_MAPPING
    assert second == TeardownReport(
        unplugged=True, unmounts=(), closes=(TOOL_MAPPING, DOLPHIN_NAME), busy=()
    )
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert record["busy"] == []
    assert record["mapping"] is None
    assert [argv for argv in fake_runner.argvs if argv[0] == UMOUNT] == [UNPLUG_UMOUNT]


def test_unplug_is_told_by_a_device_number_now_naming_another_device(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mapping=None))
    host_tree.add_block(
        SysfsDevice(kname="sdb1", devnum="8:17", syspath="/sys/devices/other/sdb1")
    )
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED)
    fake_runner.on(UNPLUG_UMOUNT, Answer())

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.unplugged is True
    assert fake_runner.argvs == [readback_argv(PERSONAL_PATH), UNPLUG_UMOUNT]


def test_unplug_removes_a_mapping_with_a_broken_tool_name_by_devnum(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mount=None))
    host_tree.add_block(
        SysfsDevice(kname="dm-0", devnum="252:0", dm_name="steamos-mounter-x")
    )
    fake_runner.on(DEPS_DM0, DEPS_ON_SDB1)
    fake_runner.on(REMOVE_DM0, Answer())

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.closes == ("steamos-mounter-x",)
    assert fake_runner.argvs == [DEPS_DM0, REMOVE_DM0]


def test_unplug_names_a_nameless_foreign_mapping_by_devnum(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mount=None))
    host_tree.add_block(SysfsDevice(kname="dm-0", devnum="252:0"))
    fake_runner.on(DEPS_DM0, DEPS_ON_SDB1)
    fake_runner.on(REMOVE_DM0, Answer(returncode=1))

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.busy == ("252:0",)


# --- deliberate stop (AC-062, AC-065) ---------------------------------------------


def test_deliberate_stop_with_a_busy_target_goes_lazy_and_deferred(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record())
    plug_sdb1(host_tree)
    host_tree.add_block(OWN_DM)
    host_tree.add_block(DOLPHIN_DM)
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED)
    fake_runner.on(NORMAL_UMOUNT, BUSY)
    fake_runner.on(UNPLUG_UMOUNT, Answer())
    fake_runner.on(CLOSE_OWN, Answer(returncode=5))
    fake_runner.on(CLOSE_OWN_DEFERRED, Answer())

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report == TeardownReport(
        unplugged=False,
        unmounts=(UnmountResult(PERSONAL_PATH, "lazy", ""),),
        closes=(TOOL_MAPPING,),
        busy=(PERSONAL_PATH, TOOL_MAPPING),
    )
    assert fake_runner.argvs == [
        readback_argv(PERSONAL_PATH),
        NORMAL_UMOUNT,
        UNPLUG_UMOUNT,
        CLOSE_OWN,
        CLOSE_OWN_DEFERRED,
    ]
    assert timeouts(fake_runner)[1:] == [20.0, 10.0, 10.0, 10.0]
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert record["state"] == "NotMounted"
    assert record["next_step"] == f"Run {CLI} mount --volume PERSONAL."
    assert record["busy"] == [PERSONAL_PATH, TOOL_MAPPING]
    assert record["mapping"] is None
    assert not personal.exists()


def test_deliberate_stop_unmounts_and_closes_normally(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record())
    plug_sdb1(host_tree)
    host_tree.add_block(OWN_DM)
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED)
    fake_runner.on(NORMAL_UMOUNT, Answer())
    fake_runner.on(CLOSE_OWN, Answer())

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report == TeardownReport(
        unplugged=False,
        unmounts=(UnmountResult(PERSONAL_PATH, "unmounted", ""),),
        closes=(TOOL_MAPPING,),
        busy=(),
    )
    assert read_record(tmp_path, PERSONAL_RECORD)["busy"] == []
    assert not personal.exists()


def test_deliberate_stop_leaves_a_foreign_mapping_alone(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mapping=DOLPHIN_MAPPING))
    plug_sdb1(host_tree)
    host_tree.add_block(DOLPHIN_DM)
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED)
    fake_runner.on(NORMAL_UMOUNT, Answer())

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.closes == ()
    assert {argv[0] for argv in fake_runner.argvs} == {FINDMNT, UMOUNT}
    assert read_record(tmp_path, PERSONAL_RECORD)["mapping"] == DOLPHIN_MAPPING


def test_deliberate_stop_with_a_mapping_already_gone(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mount=None))
    plug_sdb1(host_tree)

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report == TeardownReport(unplugged=False, unmounts=(), closes=(), busy=())
    assert fake_runner.calls == []
    assert read_record(tmp_path, PERSONAL_RECORD)["mapping"] is None


@pytest.mark.parametrize(
    ("close", "argvs"),
    [
        (Answer(returncode=1), [CLOSE_OWN]),
        (Answer(returncode=5), [CLOSE_OWN, CLOSE_OWN_DEFERRED]),
    ],
    ids=["close-failed", "deferred-close-failed"],
)
def test_deliberate_stop_reports_a_mapping_it_could_not_close(
    ctx, tmp_path, host_tree, fake_runner, personal, close, argvs
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mount=None))
    plug_sdb1(host_tree)
    host_tree.add_block(OWN_DM)
    fake_runner.on(CLOSE_OWN, close)
    fake_runner.on(CLOSE_OWN_DEFERRED, Answer(returncode=1))

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.closes == ()
    assert report.busy == (TOOL_MAPPING,)
    assert fake_runner.argvs == argvs
    assert read_record(tmp_path, PERSONAL_RECORD)["mapping"] == OWN_MAPPING


def test_a_failed_unmount_stays_mounted_and_the_sweep_tries_again(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mapping=None))
    plug_sdb1(host_tree)
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED, repeat=True)
    fake_runner.on(
        NORMAL_UMOUNT, Answer(returncode=1, stderr=b"umount: permission denied\n")
    )
    fake_runner.on(NORMAL_UMOUNT, Answer())

    first = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)
    kept = read_record(tmp_path, PERSONAL_RECORD)
    leaf_kept = personal.exists()
    second = teardown.sweep(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE, ServiceResult(*["success"] * 3)
    )

    assert first.unmounts[0].result == "failed"
    assert first.busy == (PERSONAL_PATH,)
    assert kept["mount"]["status"] == "mounted"
    assert leaf_kept is True
    assert second.unmounts == (UnmountResult(PERSONAL_PATH, "unmounted", ""),)
    assert read_record(tmp_path, PERSONAL_RECORD)["mount"]["status"] == "unmounted"
    assert not personal.exists()


def test_an_unreadable_mount_table_is_reported_and_teardown_goes_on(
    ctx, tmp_path, host_tree, fake_runner, personal, caplog
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record())
    plug_sdb1(host_tree)
    host_tree.add_block(OWN_DM)
    fake_runner.on(readback_argv(PERSONAL_PATH), Answer(returncode=2))
    fake_runner.on(CLOSE_OWN, Answer())

    with caplog.at_level(logging.ERROR, logger="steamos_mounter"):
        report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.unmounts[0].result == "failed"
    assert report.unmounts[0].detail.startswith("findmnt: exit 2")
    assert report.closes == (TOOL_MAPPING,)
    assert any(item.levelno == logging.ERROR for item in caplog.records)


def test_a_pending_target_is_unmounted_too(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    pending = dict(PERSONAL_MOUNT, status="pending")
    write_record(
        tmp_path, PERSONAL_RECORD, personal_record(mount=pending, mapping=None)
    )
    plug_sdb1(host_tree)
    fake_runner.on(readback_argv(PERSONAL_PATH), NOT_MOUNTED)

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.unmounts == (UnmountResult(PERSONAL_PATH, "absent", ""),)
    assert not personal.exists()


def test_a_record_without_a_source_is_a_deliberate_stop(
    ctx, tmp_path, fake_runner, personal
):
    write_record(
        tmp_path,
        PERSONAL_RECORD,
        personal_record(source=None, mapping=None, mount=None),
    )

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.unplugged is False
    assert fake_runner.calls == []
    assert read_record(tmp_path, PERSONAL_RECORD)["state"] == "NotMounted"


# --- the mount directory (DD-26) --------------------------------------------------


def test_a_directory_the_tool_did_not_create_stays(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    mount = dict(PERSONAL_MOUNT, created_dir=False)
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mount=mount, mapping=None))
    plug_sdb1(host_tree)
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED)
    fake_runner.on(NORMAL_UMOUNT, Answer())

    teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert personal.is_dir()


def test_a_directory_that_is_not_empty_stays(
    ctx, tmp_path, host_tree, fake_runner, personal, caplog
):
    (personal / "left-behind").write_text("x")
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mapping=None))
    plug_sdb1(host_tree)
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED)
    fake_runner.on(NORMAL_UMOUNT, Answer())

    with caplog.at_level(logging.WARNING, logger="steamos_mounter"):
        teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert (personal / "left-behind").is_file()
    assert any(PERSONAL_PATH in item.getMessage() for item in caplog.records)


def test_a_directory_already_gone_is_fine(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    personal.rmdir()
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mapping=None))
    plug_sdb1(host_tree)
    fake_runner.on(readback_argv(PERSONAL_PATH), NOT_MOUNTED)

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.busy == ()


# --- missing and unreadable records (ADR-0004 D5, DD-10) -------------------------


def test_a_missing_record_owns_nothing(ctx, tmp_path, fake_runner, caplog):
    runtime_dirs(ctx)

    with caplog.at_level(logging.DEBUG, logger="steamos_mounter"):
        report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report == TeardownReport(unplugged=False, unmounts=(), closes=(), busy=())
    assert fake_runner.calls == []
    assert not (tmp_path / PERSONAL_RECORD).exists()
    assert own_messages(caplog) == [f"{PERSONAL_DEVICE}: this instance owns nothing"]


def unreadable_personal(tmp_path, host_tree, registry: str | None) -> None:
    write_record(tmp_path, PERSONAL_RECORD, b"{not json")
    if registry is not None:
        write_registry(tmp_path, registry)
    host_tree.add_block(OWN_DM)


def test_an_unreadable_record_runs_the_fallback_sweep(
    ctx, tmp_path, host_tree, fake_runner, personal, caplog
):
    unreadable_personal(
        tmp_path, host_tree, builders.registry_text([builders.PERSONAL])
    )
    host_tree.link_by_uuid(PERSONAL_UUID, "sdb1")
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED)
    fake_runner.on(NORMAL_UMOUNT, Answer())
    fake_runner.on(CLOSE_OWN, Answer())

    with caplog.at_level(logging.WARNING, logger="steamos_mounter"):
        report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report == TeardownReport(
        unplugged=False,
        unmounts=(UnmountResult(PERSONAL_PATH, "unmounted", ""),),
        closes=(TOOL_MAPPING,),
        busy=(),
    )
    assert fake_runner.argvs == [readback_argv(PERSONAL_PATH), NORMAL_UMOUNT, CLOSE_OWN]
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert record["state"] == "NotMounted"
    assert record["reason"] == "record_unreadable"
    assert record["name"] == "PERSONAL"
    assert record["unit"] == REGISTERED_UNIT
    assert record["next_step"] == (
        f"Run {CLI} mount --volume PERSONAL; journalctl -t steamos-mounter"
        " SM_VOLUME=PERSONAL shows what was unmounted."
    )
    assert own_messages(caplog) == [
        "PERSONAL: the record is unreadable: running the fallback sweep"
    ]
    assert personal.is_dir()  # created_dir is unknown: the directory stays


def test_an_unreadable_record_of_an_unplugged_volume(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    unreadable_personal(
        tmp_path, host_tree, builders.registry_text([builders.PERSONAL])
    )
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_MOUNTED)
    fake_runner.on(UNPLUG_UMOUNT, Answer())
    fake_runner.on(CLOSE_OWN_DEFERRED, Answer())

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.unplugged is True
    assert fake_runner.argvs == [
        readback_argv(PERSONAL_PATH),
        UNPLUG_UMOUNT,
        CLOSE_OWN_DEFERRED,
    ]
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert (record["state"], record["reason"]) == ("NotPresent", "record_unreadable")
    assert record["next_step"] == (
        "Plug the drive in; journalctl -t steamos-mounter SM_VOLUME=PERSONAL"
        " shows what was unmounted."
    )


@pytest.mark.parametrize(
    "registry", [None, builders.registry_text([builders.MEDIABOX])], ids=str
)
def test_an_unreadable_record_without_a_registry_path_closes_only(
    ctx, tmp_path, host_tree, fake_runner, personal, registry
):
    unreadable_personal(tmp_path, host_tree, registry)
    host_tree.link_by_uuid(PERSONAL_UUID, "sdb1")
    fake_runner.on(CLOSE_OWN, Answer())

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.unmounts == ()
    assert fake_runner.argvs == [CLOSE_OWN]
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert record["name"] == PERSONAL_UUID
    assert record["reason"] == "record_unreadable"


def test_an_unreadable_record_of_a_path_that_is_no_uuid_closes_nothing(
    ctx, tmp_path, fake_runner
):
    runtime_dirs(ctx)
    write_record(tmp_path, "run/steamos-mounter/records/registered/abc.json", b"[]")

    report = teardown.stop(ctx, InstanceKind.REGISTERED, "/dev/disk/by-uuid/abc")

    assert report.closes == ()
    assert fake_runner.calls == []


def test_a_registered_path_that_is_no_record_key_is_refused(ctx, fake_runner):
    runtime_dirs(ctx)

    with pytest.raises(ValueError, match="not a lock key"):
        teardown.stop(ctx, InstanceKind.REGISTERED, "/dev/disk/by-uuid/..")


def test_an_unreadable_auto_record_unmounts_the_mounts_of_its_device(
    ctx, tmp_path, host_tree, fake_runner
):
    runtime_dirs(ctx)
    write_record(tmp_path, SDC1_RECORD, b"{not json")
    plug_sdc1(host_tree)
    host_tree.link_by_uuid(GAMES_UUID, "sdc1")
    make_leaf(tmp_path, GAMES_PATH)
    fake_runner.on(TABLE_ARGV, table_with_games())
    fake_runner.on(readback_argv(GAMES_PATH), GAMES_MOUNTED)
    fake_runner.on((UMOUNT, GAMES_PATH), Answer())

    report = teardown.stop(ctx, InstanceKind.AUTO, SDC1_SYSPATH)

    assert report.unmounts == (UnmountResult(GAMES_PATH, "unmounted", ""),)
    assert [argv for argv in fake_runner.argvs if argv[0] == UMOUNT] == [
        (UMOUNT, GAMES_PATH)
    ]
    record = read_record(tmp_path, SDC1_RECORD)
    assert record["kind"] == "auto"
    assert record["key"] == "sdc1-8_33"
    assert record["name"] == "sdc1"
    assert record["state"] == "NotMounted"
    assert record["reason"] == "record_unreadable"
    assert record["next_step"] == (
        f"Run {CLI} mount --device /dev/sdc1; journalctl -t steamos-mounter"
        " SM_VOLUME=sdc1 shows what was unmounted."
    )
    assert (tmp_path / "run/steamos-mounter/locks/volume-1234-abcd.lock").exists()


def test_an_unreadable_auto_record_with_an_unreadable_mount_table(
    ctx, tmp_path, fake_runner, caplog
):
    runtime_dirs(ctx)
    write_record(tmp_path, SDC1_RECORD, b"{not json")
    fake_runner.on(TABLE_ARGV, Answer(returncode=2))

    with caplog.at_level(logging.ERROR, logger="steamos_mounter"):
        report = teardown.stop(ctx, InstanceKind.AUTO, SDC1_SYSPATH)

    assert report == TeardownReport(unplugged=True, unmounts=(), closes=(), busy=())
    assert len(own_messages(caplog)) == 1
    assert read_record(tmp_path, SDC1_RECORD)["state"] == "NotPresent"


# --- auto instances (I007) --------------------------------------------------------


def test_an_unplugged_auto_volume_locks_on_its_record_key(
    ctx, tmp_path, host_tree, fake_runner
):
    runtime_dirs(ctx)
    write_record(tmp_path, SDC1_RECORD, games_record(mount=None))
    host_tree.link_by_uuid(GAMES_UUID, "sdb1")  # a link is left, but not to sdc1

    report = teardown.stop(ctx, InstanceKind.AUTO, SDC1_SYSPATH)

    assert report.unplugged is True
    locks = tmp_path / "run/steamos-mounter/locks"
    assert sorted(path.name for path in locks.iterdir()) == ["volume-sdc1-8_33.lock"]


def test_a_present_auto_volume_locks_on_its_filesystem_uuid(
    ctx, tmp_path, host_tree, fake_runner
):
    runtime_dirs(ctx)
    write_record(tmp_path, SDC1_RECORD, games_record(mount=None))
    plug_sdc1(host_tree)
    host_tree.link_by_uuid("0000-0000", "sdb1")
    host_tree.link_by_uuid("not a key", "sdc1")
    host_tree.link_by_uuid(GAMES_UUID, "sdc1")

    report = teardown.stop(ctx, InstanceKind.AUTO, SDC1_SYSPATH)

    assert report.unplugged is False
    locks = tmp_path / "run/steamos-mounter/locks"
    assert sorted(path.name for path in locks.iterdir()) == ["volume-1234-abcd.lock"]
    record = read_record(tmp_path, SDC1_RECORD)
    assert record["next_step"] == f"Run {CLI} mount --device /dev/sdc1."


def test_an_auto_record_of_another_device_path_is_not_this_instances(
    ctx, tmp_path, fake_runner
):
    runtime_dirs(ctx)
    other = dict(SDC1_SOURCE, syspath="/sys/devices/elsewhere/sdc1")
    write_record(tmp_path, SDC1_RECORD, games_record(source=other))

    report = teardown.stop(ctx, InstanceKind.AUTO, SDC1_SYSPATH)

    assert report == TeardownReport(unplugged=False, unmounts=(), closes=(), busy=())
    assert fake_runner.calls == []
    assert read_record(tmp_path, SDC1_RECORD)["state"] == "MountedRW"


def test_an_auto_instance_takes_the_first_unreadable_record_of_its_kname(
    ctx, tmp_path, fake_runner
):
    runtime_dirs(ctx)
    auto = "run/steamos-mounter/records/auto"
    other = dict(SDC1_SOURCE, syspath="/sys/devices/elsewhere/sdc1")
    write_record(
        tmp_path,
        f"{auto}/sdc1-8_30.json",
        games_record(key="sdc1-8_30", source=other, mount=None),
    )
    write_record(tmp_path, SDC1_RECORD, b"{not json")
    write_record(tmp_path, f"{auto}/sdc1-8_99.json", b"[]")
    write_record(tmp_path, f"{auto}/sdc10-8_160.json", b"")
    write_record(tmp_path, f"{auto}/sdc1-8_33.txt", b"")
    fake_runner.on(TABLE_ARGV, Answer.from_fixture("findmnt-real-list.json"))

    teardown.stop(ctx, InstanceKind.AUTO, SDC1_SYSPATH)

    assert read_record(tmp_path, SDC1_RECORD)["reason"] == "record_unreadable"
    assert (tmp_path / auto / "sdc1-8_99.json").read_bytes() == b"[]"
    assert read_record(tmp_path, f"{auto}/sdc1-8_30.json")["state"] == "MountedRW"


def test_a_record_without_a_syspath_is_a_deliberate_stop(
    ctx, tmp_path, host_tree, fake_runner, personal
):
    source = {"kname": "sdb1", "devnum": "8:17", "syspath": None}
    write_record(
        tmp_path,
        PERSONAL_RECORD,
        personal_record(source=source, mapping=None, mount=None),
    )
    plug_sdb1(host_tree)

    report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)

    assert report.unplugged is False


def test_an_auto_instance_without_a_records_directory_owns_nothing(ctx, fake_runner):
    report = teardown.stop(ctx, InstanceKind.AUTO, SDC1_SYSPATH)

    assert report.unmounts == ()
    assert fake_runner.calls == []


# --- the sweep (ExecStopPost=) ----------------------------------------------------


def test_the_sweep_logs_a_failed_service_result_at_error_and_stores_it(
    ctx, tmp_path, host_tree, fake_runner, personal, caplog
):
    done = dict(PERSONAL_MOUNT, status="unmounted")
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mount=done, mapping=None))
    plug_sdb1(host_tree)

    with caplog.at_level(logging.DEBUG, logger="steamos_mounter"):
        teardown.sweep(
            ctx,
            InstanceKind.REGISTERED,
            PERSONAL_DEVICE,
            ServiceResult(result="timeout", exit_code="killed", exit_status="TERM"),
        )

    errors = [item for item in caplog.records if item.levelno == logging.ERROR]
    assert len(errors) == 1
    assert errors[0].getMessage() == (
        "PERSONAL: service result timeout, exit code killed, exit status TERM"
    )
    assert sm_fields(errors[0]) == {
        "SM_VOLUME": "PERSONAL",
        "SM_UUID": PERSONAL_UUID,
        "SM_DEVICE": "/dev/sdb1",
        "SM_EVENT": "sweep",
        "SM_STATE": "NotMounted",
        "SM_REASON": "timeout",
        "SM_UNIT": REGISTERED_UNIT,
    }
    assert read_record(tmp_path, PERSONAL_RECORD)["service"] == {
        "result": "timeout",
        "exit_code": "killed",
        "exit_status": "TERM",
        "at": NOW,
    }
    assert fake_runner.calls == []


def test_the_sweep_logs_success_at_notice(
    ctx, tmp_path, host_tree, fake_runner, personal, caplog
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record(mount=None, mapping=None))
    plug_sdb1(host_tree)

    with caplog.at_level(logging.DEBUG, logger="steamos_mounter"):
        teardown.sweep(
            ctx,
            InstanceKind.REGISTERED,
            PERSONAL_DEVICE,
            ServiceResult(result="success", exit_code="exited", exit_status="0"),
        )

    levels = {item.getMessage(): item.levelno for item in caplog.records}
    assert (
        levels["PERSONAL: service result success, exit code exited, exit status 0"]
        == NOTICE
    )
    assert logging.ERROR not in levels.values()


def test_the_sweep_deletes_an_auto_record_after_an_unplug(ctx, tmp_path, fake_runner):
    runtime_dirs(ctx)
    write_record(tmp_path, SDC1_RECORD, games_record(mount=None))

    report = teardown.sweep(
        ctx, InstanceKind.AUTO, SDC1_SYSPATH, ServiceResult("success", "exited", "0")
    )

    assert report.unplugged is True
    assert not (tmp_path / SDC1_RECORD).exists()


def test_the_sweep_keeps_an_auto_record_after_a_deliberate_stop(
    ctx, tmp_path, host_tree, fake_runner
):
    runtime_dirs(ctx)
    write_record(tmp_path, SDC1_RECORD, games_record(mount=None))
    plug_sdc1(host_tree)

    teardown.sweep(
        ctx, InstanceKind.AUTO, SDC1_SYSPATH, ServiceResult("success", "exited", "0")
    )

    assert read_record(tmp_path, SDC1_RECORD)["service"]["result"] == "success"


@pytest.mark.parametrize(
    ("result", "errors"), [("success", 0), ("exit-code", 1), (None, 1)]
)
def test_the_sweep_of_an_instance_that_owns_nothing(
    ctx, tmp_path, fake_runner, caplog, result, errors
):
    runtime_dirs(ctx)

    with caplog.at_level(logging.DEBUG, logger="steamos_mounter"):
        teardown.sweep(
            ctx,
            InstanceKind.REGISTERED,
            PERSONAL_DEVICE,
            ServiceResult(result, "exited", "1"),
        )

    found = [item for item in caplog.records if item.levelno == logging.ERROR]
    assert len(found) == errors
    assert not (tmp_path / PERSONAL_RECORD).exists()
    assert fake_runner.calls == []


# --- locking and the service result -----------------------------------------------


def test_a_held_volume_lock_stops_the_teardown(
    ctx, tmp_path, fake_runner, personal, monkeypatch
):
    write_record(tmp_path, PERSONAL_RECORD, personal_record())
    monkeypatch.setattr(teardown, "LOCK_WAIT", 0.0)
    holder = os.open(tmp_path / PERSONAL_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        with pytest.raises(LockTimeout):
            teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE)
    finally:
        os.close(holder)

    assert fake_runner.calls == []
    assert read_record(tmp_path, PERSONAL_RECORD)["state"] == "MountedRW"


def test_service_result_from_the_environment():
    environment = {
        "SERVICE_RESULT": "exit-code",
        "EXIT_CODE": "exited",
        "EXIT_STATUS": "",
        "OTHER": "x",
    }

    assert ServiceResult.from_environment(environment) == ServiceResult(
        result="exit-code", exit_code="exited", exit_status=None
    )
    assert ServiceResult.from_environment({}) == ServiceResult(None, None, None)
