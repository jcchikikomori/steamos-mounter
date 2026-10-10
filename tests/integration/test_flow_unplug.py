"""Surprise-unplug teardown with own and foreign mappings - integration tests.

Design Doc: docs/design/steamos-mounter-design.md (sections "Teardown",
"Unplug Teardown" diagram, "BitLocker Unlock and Mappings" (dmsetup deps,
DD-15), "Records and Teardown" EARS criteria). Generated 2026-10-08 by the
acceptance-test-generator. Budget used: 3/3 integration for the feature
"removal and external unmounts" (FR-08).

Test boundary: FakeRunner for umount, dmsetup, cryptsetup, findmnt; real
records, sysfs and the created mount directory under HostPaths(root=tmp_path).
Unplug is simulated by leaving /sys/dev/block/<M:m> unresolvable while
/sys/block/dm-*/ still lists the stacked mappings.

Fixtures expected from tests/conftest.py: fake_runner, fake_platform, host_tree,
fake_clock, ctx.
"""

import json
import logging
from pathlib import Path

import pytest
from tests.helpers import builders
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import (
    CRYPTSETUP,
    DMSETUP,
    make_leaf,
    read_record,
    readback_argv,
    runtime_dirs,
    sm_fields,
    write_record,
    write_registry,
)
from tests.helpers.host_tree import SysfsDevice

from steamos_mounter.escape import escape_path, unit_name
from steamos_mounter.journal import NOTICE
from steamos_mounter.model import InstanceKind
from steamos_mounter.mounter import UnmountResult
from steamos_mounter.platforms.steamos import TOOLS
from steamos_mounter.routing import AUTO_TEMPLATE

teardown = pytest.importorskip("steamos_mounter.teardown")
state = pytest.importorskip("steamos_mounter.state")

PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
PERSONAL_DEVICE_PATH = f"/dev/disk/by-uuid/{PERSONAL_UUID}"
PERSONAL_RECORD = f"run/steamos-mounter/records/registered/{PERSONAL_UUID}.json"
MAPPING_NAME = f"steamos-mounter-{PERSONAL_UUID}"
GAMES_PATH = "/run/media/deck/GAMES"
SDC1_SYSPATH = (
    "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-2/2-2:1.0/host1/"
    "target1:0:0/1:0:0:0/block/sdc/sdc1"
)
SDC1_RECORD = "run/steamos-mounter/records/auto/sdc1-8_33.json"
DMSETUP_DEPS_ON_SDB1 = b"1 dependencies\t: (8, 17)\n"
SDB1_SYSPATH = "/sys/devices/pci0000:00/0000:00:08.1/usb4/4-1/block/sdb/sdb1"
DOLPHIN_NAME = "PAT4T4SHUAWEI_PERSONAL_4_3_2024"  # dm-1's label-derived name
REGISTERED_UNIT = unit_name("steamos-mounter@", escape_path(PERSONAL_DEVICE_PATH))
AUTO_UNIT = unit_name(AUTO_TEMPLATE, escape_path(SDC1_SYSPATH))
UMOUNT = TOOLS.umount
NOW = "2026-10-08T02:11:40Z"  # FakeClock's default start
TEARDOWN_LOGGERS = "steamos_mounter.teardown"  # teardown and teardown_report
PERSONAL_NTFS3_RW = Answer.from_fixture("findmnt-personal-ntfs3-rw.json", returncode=0)
GAMES_EXFAT_RW = Answer.from_fixture("findmnt-games-exfat-rw.json", returncode=0)


def personal_record() -> bytes:
    """The Design Doc "Record Schema" example, mounted read-write on dm-0."""
    record = builders.record_dict(
        state="MountedRW",
        reason=None,
        warning=None,
        next_step="-",
        unit=REGISTERED_UNIT,
        source={"kname": "sdb1", "devnum": "8:17", "syspath": SDB1_SYSPATH},
    )
    return json.dumps(record).encode()


def games_record() -> bytes:
    """The auto record test_flow_unregistered_exfat leaves for GAMES on sdc1."""
    record = builders.record_dict(
        kind="auto",
        key="sdc1-8_33",
        name="GAMES",
        unit=AUTO_UNIT,
        state="MountedRW",
        reason=None,
        warning=None,
        next_step="-",
        source={"kname": "sdc1", "devnum": "8:33", "syspath": SDC1_SYSPATH},
        mapping=None,
        mount={
            "status": "mounted",
            "target": GAMES_PATH,
            "device": "/dev/sdc1",
            "devnum": "8:33",
            "driver": "exfat",
            "mode": "rw",
            "created_dir": True,
        },
        attempt={"probe": None, "steps": [], "skipped": []},
    )
    return json.dumps(record).encode()


@pytest.fixture
def expected_unplug_argv() -> list[tuple[str, ...]]:
    """Teardown actions (umount, dmsetup, cryptsetup), in order; the findmnt read
    is separate."""
    return [
        ("/usr/bin/umount", "-l", PERSONAL_PATH),
        ("/usr/bin/dmsetup", "deps", "-o", "devno", "-j", "252", "-m", "0"),
        ("/usr/bin/dmsetup", "deps", "-o", "devno", "-j", "252", "-m", "1"),
        ("/usr/bin/cryptsetup", "close", "--deferred", MAPPING_NAME),
        ("/usr/bin/dmsetup", "remove", "--deferred", "-j", "252", "-m", "1"),
    ]


# AC-031: "Given a mounted volume (any driver, BitLocker or not), when the drive
#   is unplugged without unmounting, then within 15 seconds findmnt shows no
#   mount for it, dmsetup ls shows no mapping for it, and no ntfs-3g process for
#   it is running."
# EARS "Records and Teardown": "When a foreign mapping must be removed at unplug,
#   the system shall address it by device number only." (DD-15)
# ROI: 99 (BV:10 x Freq:9 + Legal:0 + Defect:9)
# Behavior: BindsTo stop -> ExecStop teardown reads the record, source devnum
#   gone -> umount -l target -> dmsetup deps per dm-N -> own mapping closed
#   --deferred, foreign removed --deferred by devnum -> rmdir created dir ->
#   record NotPresent -> ExecStopPost sweep is a no-op and stores the result
# @category: core-functionality
# @dependency: teardown, state, bitlocker, mounter, blockdev, locks
# @complexity: high
# @real-dependency: tmp_path record, sysfs (/sys/block/dm-0, dm-1; no
#   /sys/dev/block/8:17), created mount dir, flock (volume lock)
def test_unplug_closes_own_and_foreign_mappings_by_devnum(
    tmp_path: Path,
    ctx,
    host_tree,
    fake_runner,
    expected_unplug_argv,
    caplog,
    no_holders,
) -> None:
    """Design Doc "Unplug Teardown" with one own and one foreign mapping.

    Given
      - HostPaths(root=tmp_path): record tmp_path/PERSONAL_RECORD as in the
        Design Doc "Record Schema" example (state MountedRW, source devnum
        "8:17", mapping dm-0 "252:0" opened_by "handler", mount.target
        PERSONAL_PATH, mount.created_dir true); the leaf dir
        tmp_path/run/media/deck/PERSONAL exists and is empty; sysfs has
        /sys/block/dm-0 and /sys/block/dm-1 (a second, Dolphin-named mapping
        on the same container) and no /sys/dev/block/8:17 (unplugged).
      - FakeRunner script:
        findmnt ... --mountpoint /run/media/deck/PERSONAL
            -> fixtures/synthetic/findmnt-personal-ntfs3-rw.json
        umount -l /run/media/deck/PERSONAL -> rc 0
        dmsetup deps -o devno -j 252 -m 0 -> DMSETUP_DEPS_ON_SDB1
        dmsetup deps -o devno -j 252 -m 1 -> DMSETUP_DEPS_ON_SDB1
        cryptsetup close --deferred <MAPPING_NAME> -> rc 0
        dmsetup remove --deferred -j 252 -m 1 -> rc 0
    When
      - report = teardown.stop(ctx, InstanceKind.REGISTERED,
        PERSONAL_DEVICE_PATH)
      - then teardown.sweep(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH,
        ServiceResult(result="success", exit_code="exited", exit_status="0"))
    Then (pass criteria)
      - report.unplugged is True; report.unmounts == (UnmountResult(target
        PERSONAL_PATH, result "lazy", ...),); report.closes names both
        mappings; report.busy == ()
      - the FakeRunner log is the one findmnt read of the target
        (mounter.unmount checks there is a mount before it runs umount), then
        expected_unplug_argv, in that order; no
        argv contains dm-1's label-derived name (DD-15), no normal umount
        without -l, and no sysfs holders/ read decides anything (ADR-0001
        guidance 10: /sys/class/block/sdb1/holders is absent in this setup)
      - tmp_path/run/media/deck/PERSONAL no longer exists (created_dir true,
        empty); the record now reads state "NotPresent", mount.status
        "unmounted", mapping null or closed, busy []
      - the sweep adds no umount, cryptsetup or dmsetup call; the record's
        service block is {"result": "success", "exit_code": "exited",
        "exit_status": "0", "at": <FakeClock now>}; caplog has no ERROR
    """
    runtime_dirs(ctx)
    write_record(tmp_path, PERSONAL_RECORD, personal_record())
    leaf = make_leaf(tmp_path, PERSONAL_PATH)
    host_tree.add_block(
        SysfsDevice(
            kname="dm-0", devnum="252:0", dm_name=MAPPING_NAME, slaves=("sdb1",)
        )
    )
    host_tree.add_block(
        SysfsDevice(
            kname="dm-1", devnum="252:1", dm_name=DOLPHIN_NAME, slaves=("sdb1",)
        )
    )
    deps = Answer(stdout=DMSETUP_DEPS_ON_SDB1)
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_NTFS3_RW)
    fake_runner.on((UMOUNT, "-l", PERSONAL_PATH), Answer())
    fake_runner.on(expected_unplug_argv[1], deps)
    fake_runner.on(expected_unplug_argv[2], deps)
    fake_runner.on((CRYPTSETUP, "close", "--deferred", MAPPING_NAME), Answer())
    fake_runner.on(expected_unplug_argv[4], Answer())

    with caplog.at_level(logging.DEBUG):
        report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH)
        calls_after_stop = len(fake_runner.calls)
        teardown.sweep(
            ctx,
            InstanceKind.REGISTERED,
            PERSONAL_DEVICE_PATH,
            teardown.ServiceResult(
                result="success", exit_code="exited", exit_status="0"
            ),
        )

    assert report.unplugged is True
    assert report.unmounts == (UnmountResult(PERSONAL_PATH, "lazy", ""),)
    assert report.closes == (MAPPING_NAME, DOLPHIN_NAME)
    assert report.busy == ()
    assert fake_runner.argvs == [readback_argv(PERSONAL_PATH), *expected_unplug_argv]
    assert not any(DOLPHIN_NAME in item for argv in fake_runner.argvs for item in argv)
    assert (UMOUNT, PERSONAL_PATH) not in fake_runner.argvs
    assert not leaf.exists()
    assert leaf.parent.is_dir()
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert record["state"] == "NotPresent"
    assert record["mount"]["status"] == "unmounted"
    assert record["mapping"] is None
    assert record["busy"] == []
    assert len(fake_runner.calls) == calls_after_stop
    assert record["service"] == {
        "result": "success",
        "exit_code": "exited",
        "exit_status": "0",
        "at": NOW,
    }
    assert not [item for item in caplog.records if item.levelno >= logging.ERROR]


# EARS "Records and Teardown": "If a record is missing at teardown, then the
#   instance shall unmount nothing; if it is unreadable, then the instance shall
#   run the fallback sweep and report it." (ADR-0004 D5, ADR-0001 guidance 9)
# ROI: 29 (BV:7 x Freq:3 + Legal:0 + Defect:8)
# Behavior: record state decides between "owns nothing" and the fallback sweep
#   over the registry path and the tool mapping name
# @category: edge-case
# @dependency: teardown, state, config, mounts, bitlocker
# @complexity: medium
# @real-dependency: tmp_path record (absent or garbage), registry
@pytest.mark.parametrize("record", ["missing", "unreadable"])
def test_teardown_without_usable_record_owns_nothing_or_falls_back(
    record: str,
    tmp_path: Path,
    ctx,
    host_tree,
    fake_runner,
    caplog,
) -> None:
    """A missing record means no action; garbage means the fallback sweep.

    Given
      - registry with PERSONAL (fixed path PERSONAL_PATH); "missing": no file
        at tmp_path/PERSONAL_RECORD; "unreadable": the file holds b"{not json"
      - the device is present (by-uuid link to sdb1, dm-0 named MAPPING_NAME),
        so the fallback runs as a deliberate stop: a normal unmount and a
        normal close, --deferred only when busy (Design Doc "Teardown")
      - FakeRunner (only consulted in the "unreadable" case):
        findmnt ... --mountpoint /run/media/deck/PERSONAL
            -> fixtures/synthetic/findmnt-personal-ntfs3-rw.json
        umount /run/media/deck/PERSONAL -> rc 0
        cryptsetup close <MAPPING_NAME> -> rc 0
    When
      - report = teardown.stop(ctx, InstanceKind.REGISTERED,
        PERSONAL_DEVICE_PATH)
    Then (pass criteria)
      - "missing": the FakeRunner log is empty; report.unmounts == () and
        report.closes == (); no record is created; one DEBUG/NOTICE line says
        the instance owns nothing
      - "unreadable": one umount of PERSONAL_PATH (from the registry, not the
        record) and one cryptsetup close of MAPPING_NAME (the tool name, never
        a sysfs-derived name); report says fallback (a field or reason
        "record_unreadable"); the garbage file is replaced by a valid record
        with state NotMounted (the device is present) and reason
        "record_unreadable";
        caplog has one WARNING naming the fallback sweep
    """
    runtime_dirs(ctx)
    write_registry(tmp_path, builders.registry_text([builders.PERSONAL]))
    leaf = make_leaf(tmp_path, PERSONAL_PATH)
    host_tree.add_block(SysfsDevice(kname="sdb", devnum="8:16"))
    host_tree.add_block(
        SysfsDevice(kname="sdb1", devnum="8:17", parent="sdb", syspath=SDB1_SYSPATH)
    )
    host_tree.link_by_uuid(PERSONAL_UUID, "sdb1")
    host_tree.add_block(SysfsDevice(kname="dm-0", devnum="252:0", dm_name=MAPPING_NAME))
    if record == "unreadable":
        write_record(tmp_path, PERSONAL_RECORD, b"{not json")
    fake_runner.on(readback_argv(PERSONAL_PATH), PERSONAL_NTFS3_RW)
    fake_runner.on((UMOUNT, PERSONAL_PATH), Answer())
    fake_runner.on((CRYPTSETUP, "close", MAPPING_NAME), Answer())

    with caplog.at_level(logging.DEBUG, logger="steamos_mounter"):
        report = teardown.stop(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH)

    own = [item for item in caplog.records if item.name.startswith(TEARDOWN_LOGGERS)]
    if record == "missing":
        assert fake_runner.argvs == []
        assert report.unmounts == ()
        assert report.closes == ()
        assert not (tmp_path / PERSONAL_RECORD).exists()
        assert [item.getMessage() for item in own] == [
            f"{PERSONAL_DEVICE_PATH}: this instance owns nothing"
        ]
        return
    assert fake_runner.argvs == [
        readback_argv(PERSONAL_PATH),
        (UMOUNT, PERSONAL_PATH),
        (CRYPTSETUP, "close", MAPPING_NAME),
    ]
    assert report.unmounts == (UnmountResult(PERSONAL_PATH, "unmounted", ""),)
    assert report.closes == (MAPPING_NAME,)
    saved = read_record(tmp_path, PERSONAL_RECORD)
    assert saved["state"] == "NotMounted"
    assert saved["reason"] == "record_unreadable"
    warnings = [item.getMessage() for item in own if item.levelno == logging.WARNING]
    assert warnings == [
        "PERSONAL: the record is unreadable: running the fallback sweep"
    ]
    assert leaf.is_dir()  # who created it is unknown: never removed (DD-26)


# AC-031 for the auto path and Design Doc "Teardown" 3: "An auto record is
#   deleted after a sweep at unplug." AC-033 last clause: "a later unplug leaves
#   no orphaned mapping."
# ROI: 56 (BV:8 x Freq:6 + Legal:0 + Defect:8)
# Behavior: unregistered GAMES stick yanked -> umount -l -> rmdir leaf ->
#   sweep deletes records/auto/sdc1-8_33.json
# @category: core-functionality
# @dependency: teardown, state, mounter
# @complexity: medium
# @real-dependency: tmp_path auto record, created mount dir, sysfs
def test_auto_unplug_removes_mount_dir_and_deletes_record(
    tmp_path: Path, ctx, fake_runner, caplog
) -> None:
    """The auto instance leaves no record and no directory behind at unplug.

    Given
      - record tmp_path/SDC1_RECORD from test_flow_unregistered_exfat (state
        MountedRW, mount.target GAMES_PATH, created_dir true, mapping null,
        source devnum "8:33"); tmp_path/run/media/deck/GAMES exists, empty;
        no /sys/dev/block/8:33
      - FakeRunner: umount -l /run/media/deck/GAMES -> rc 0
    When
      - teardown.stop(ctx, InstanceKind.AUTO, SDC1_SYSPATH)
      - teardown.sweep(ctx, InstanceKind.AUTO, SDC1_SYSPATH,
        ServiceResult(result="success", exit_code="killed",
        exit_status="TERM"))
    Then (pass criteria)
      - exactly one umount -l call and no dmsetup or cryptsetup call
      - tmp_path/run/media/deck/GAMES is gone; tmp_path/run/media/deck stays
        (never removed, only the leaf, DD-26)
      - after the sweep tmp_path/SDC1_RECORD does not exist; the sweep logged
        the service result at NOTICE (result "success" is not an error) with
        SM_VOLUME=GAMES
      - a second teardown.stop on the same path makes no call (idempotent,
        ADR-0001 Decision 3)
    """
    runtime_dirs(ctx)
    write_record(tmp_path, SDC1_RECORD, games_record())
    leaf = make_leaf(tmp_path, GAMES_PATH)
    fake_runner.on(readback_argv(GAMES_PATH), GAMES_EXFAT_RW)
    fake_runner.on((UMOUNT, "-l", GAMES_PATH), Answer())

    with caplog.at_level(logging.DEBUG, logger="steamos_mounter"):
        report = teardown.stop(ctx, InstanceKind.AUTO, SDC1_SYSPATH)
        teardown.sweep(
            ctx,
            InstanceKind.AUTO,
            SDC1_SYSPATH,
            teardown.ServiceResult(
                result="success", exit_code="killed", exit_status="TERM"
            ),
        )
    calls = len(fake_runner.calls)
    again = teardown.stop(ctx, InstanceKind.AUTO, SDC1_SYSPATH)

    assert report.unplugged is True
    assert [argv for argv in fake_runner.argvs if argv[0] == UMOUNT] == [
        (UMOUNT, "-l", GAMES_PATH)
    ]
    assert {DMSETUP, CRYPTSETUP}.isdisjoint(argv[0] for argv in fake_runner.argvs)
    assert not leaf.exists()
    assert (tmp_path / "run/media/deck").is_dir()
    assert not (tmp_path / SDC1_RECORD).exists()
    service = [
        item
        for item in caplog.records
        if item.getMessage().startswith("GAMES: service result success")
    ]
    assert [item.levelno for item in service] == [NOTICE]
    assert sm_fields(service[0])["SM_VOLUME"] == "GAMES"
    assert again.unmounts == ()
    assert len(fake_runner.calls) == calls
