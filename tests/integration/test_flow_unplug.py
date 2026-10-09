"""Surprise-unplug teardown with own and foreign mappings - integration skeleton.

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
fake_clock, ctx. Skipped until steamos_mounter.teardown exists.
"""

from pathlib import Path

import pytest

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


@pytest.fixture
def expected_unplug_argv() -> list[tuple[str, ...]]:
    """Tool calls of an unplug teardown, in order (Design Doc "Teardown")."""
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
def test_unplug_closes_own_and_foreign_mappings_by_devnum(tmp_path: Path) -> None:
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
      - the FakeRunner log equals expected_unplug_argv (order included); no
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
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")


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
) -> None:
    """A missing record means no action; garbage means the fallback sweep.

    Given
      - registry with PERSONAL (fixed path PERSONAL_PATH); "missing": no file
        at tmp_path/PERSONAL_RECORD; "unreadable": the file holds b"{not json"
      - FakeRunner (only consulted in the "unreadable" case):
        findmnt ... --mountpoint /run/media/deck/PERSONAL
            -> fixtures/synthetic/findmnt-personal-ntfs3-rw.json
        umount /run/media/deck/PERSONAL -> rc 0
        cryptsetup close --deferred <MAPPING_NAME> -> rc 4 (absent)
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
        with state NotPresent or NotMounted and reason "record_unreadable";
        caplog has one WARNING naming the fallback sweep
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")


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
def test_auto_unplug_removes_mount_dir_and_deletes_record(tmp_path: Path) -> None:
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
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")
