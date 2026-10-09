"""Dolphin unlock of an unregistered BitLocker drive - integration skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "Dolphin-unlock
Path", "Device Classification and Routing" (Mapping, AUTO_MOUNT_INNER),
"Delegation" EARS criteria, DD-12). Generated 2026-10-08 by the
acceptance-test-generator. Budget used: 2/3 integration for the feature
"unregistered BitLocker" (FR-06).

Test boundary: FakeRunner for lsblk, findmnt, systemctl, probe, mount; real
files, locks and records under HostPaths(root=tmp_path); FakeKernelLog.

Synthetic tree: fixtures/synthetic/lsblk-tree-dolphin-unregistered.json (first
line "# synthetic: real tree plus removable sdc with sdc1 BitLocker uuid
7c1e4b2a-9d3f-4e5a-8b6c-0d1e2f3a4b5c MAJ:MIN 8:33, and crypt dm-1 MAJ:MIN 252:1
ntfs label OBAMA uuid 3C5E7A9B1D2F4E60 with pkname sdc1"). The host tree gives
/sys/class/block/dm-1/slaves/sdc1 and /sys/block/dm-1/dm/name with a
label-derived udisks name (shape as in fixtures/deck/udev-dm-0.txt), never the
steamos-mounter- prefix.

Fixtures expected from tests/conftest.py: fake_runner, fake_platform, host_tree,
fake_kmsg, fake_clock, ctx. Skipped until steamos_mounter.reconcile exists.
"""

from pathlib import Path

import pytest

reconcile = pytest.importorskip("steamos_mounter.reconcile")
systemd = pytest.importorskip("steamos_mounter.systemd")
escape = pytest.importorskip("steamos_mounter.escape")

OBAMA_PATH = "/run/media/deck/OBAMA"
DM1_SYSPATH = "/sys/devices/virtual/block/dm-1"
SDC1_SYSPATH = (
    "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-2/2-2:1.0/host1/"
    "target1:0:0/1:0:0:0/block/sdc/sdc1"
)
SDC1_RECORD = "run/steamos-mounter/records/auto/sdc1-8_33.json"
DM1_RECORD = "run/steamos-mounter/records/auto/dm-1-252_1.json"
NTFS_RW_OPTIONS = "nosuid,nodev,uid=1000,gid=1000,umask=0022,windows_names"


@pytest.fixture
def partition_auto_unit() -> str:
    """The delegate target: the auto instance of the container's partition."""
    return escape.unit_name(
        "steamos-mounter-auto@",
        escape.auto_instance(SDC1_SYSPATH),
    )


# AC-026: "Given the owner unlocks it in Dolphin, then its inner filesystem is
#   mounted at /run/media/deck/<sanitized LABEL> within the latency target of
#   the unlock. If udisks or Dolphin already mounted it, it is not mounted a
#   second time."
# Design-level EARS "Delegation": the dm instance requests a reload of the
#   partition instance and never mounts by itself.
# ROI: 43 (BV:7 x Freq:5 + Legal:0 + Defect:8)
# Behavior: dm-1 add event -> dm instance routes DELEGATE (slave sdc1 BitLocker,
#   foreign name) -> request_reconcile reloads the sdc1 auto instance -> that
#   instance routes AUTO_MOUNT_INNER -> chain on /dev/dm-1 -> MountedRW at
#   /run/media/deck/OBAMA, mapping opened_by "other", no cryptsetup call
# @category: core-functionality
# @dependency: reconcile, routing, systemd, escape, bitlocker (discovery only),
#   mounter, ntfs, mounts, state, locks
# @complexity: high
# @real-dependency: tmp_path sysfs (slaves/, dm/name), records, flock
def test_dolphin_unlock_delegates_then_mounts_inner_under_auto_path(
    tmp_path: Path,
) -> None:
    """Design Doc "Dolphin-unlock Path", unregistered branch.

    Given
      - HostPaths(root=tmp_path): empty registry, OS set known, /run/media/deck
        present, sysfs: /sys/class/block/dm-1/slaves/sdc1,
        /sys/block/dm-1/dm/name = "<udisks label-derived name>",
        /sys/class/block/sdc1/holders/dm-1.
      - FakeRunner script:
        lsblk ... -> fixtures/synthetic/lsblk-tree-dolphin-unregistered.json
        systemctl show -p LoadState,ActiveState,SubState,Result
            <partition_auto_unit> -> "LoadState=loaded\\nActiveState=active..."
        systemctl reload --no-block <partition_auto_unit> -> rc 0
        findmnt ... --list --real -> fixtures/deck/findmnt-real-list.json
            (no /dev/dm-1 entry)
        ntfs-3g.probe --readwrite /dev/dm-1 -> rc 0
        mount -i -t ntfs3 -o <NTFS_RW_OPTIONS> /dev/dm-1 /run/media/deck/OBAMA
            -> rc 0
        findmnt ... --mountpoint /run/media/deck/OBAMA
            -> fixtures/synthetic/findmnt-obama-ntfs3-rw.json
    When
      - reconcile.run(ctx, InstanceKind.AUTO, DM1_SYSPATH, Trigger.START)
      - reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.RELOAD)
        (what systemd runs for the reload the first pass requested)
    Then (pass criteria)
      - first outcome: route.action == Action.DELEGATE with delegate_unit ==
        partition_auto_unit; systemd.request_reconcile result "reloaded"; the
        log shows one systemctl show and one systemctl reload --no-block, no
        systemctl start; tmp_path/DM1_RECORD does not exist (delegating
        instances own nothing)
      - second outcome: route.action == Action.AUTO_MOUNT_INNER, state
        MountedRW, mount.device "/dev/dm-1", mount.target OBAMA_PATH; the
        name comes from the inner label OBAMA, never from the dm name
      - no cryptsetup or dmsetup call anywhere (FR-06: Dolphin did the unlock)
      - record tmp_path/SDC1_RECORD: mapping {"kname": "dm-1", "devnum":
        "252:1", "opened_by": "other", "save_pending": false}, source.kname
        "sdc1", source.devnum "8:33" (the teardown key, ADR-0002 D4.5)
      - no key unit start (unregistered: never a prompt, AC-025 spirit)
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")


# AC-026 second sentence and AC-034: "Given a partition that is already mounted
#   or held by another component (udisks, holo-automount, or an earlier run),
#   when an event arrives for it, then it is not mounted again and the decision
#   is logged."
# ROI: 31 (BV:6 x Freq:4 + Legal:0 + Defect:7)
# Behavior: udisks mounted /dev/dm-1 first -> held check finds it elsewhere ->
#   MountedElsewhere with the target, no mount call, journal NOTICE
# @category: edge-case
# @dependency: reconcile, routing, mounts, state
# @complexity: medium
# @real-dependency: tmp_path records, flock
def test_dolphin_unlock_mounted_first_by_udisks_is_left_alone(
    tmp_path: Path,
) -> None:
    """Held check wins over the chain when udisks got there first.

    Given
      - the same tree and sysfs as the test above
      - FakeRunner: findmnt ... --list --real ->
        fixtures/synthetic/findmnt-list-dm1-at-udisks-path.json, which lists
        /dev/dm-1 (MAJ:MIN 252:1) mounted at /run/media/deck/OBAMA by udisks
    When
      - reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.RELOAD)
    Then (pass criteria)
      - outcome.state == VolumeState.MOUNTED_ELSEWHERE with the udisks target in
        the reason; no probe, mount or ntfs-3g call in the log
      - record tmp_path/SDC1_RECORD state "MountedElsewhere", mount.status not
        "mounted" by this tool (no created_dir), next_step names the target
        ("Unmount it there, then ..." per state.next_step)
      - caplog holds one NOTICE with SM_EVENT=reconcile, SM_STATE=
        MountedElsewhere, SM_REASON naming /run/media/deck/OBAMA (AC-034)
      - no notification is sent (MountedElsewhere is not in the notify list)
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")
