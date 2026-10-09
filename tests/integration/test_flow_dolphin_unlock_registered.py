"""Dolphin unlock of the registered BitLocker drive (PERSONAL) - skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "Dolphin-unlock
Path" (registered branch), "Device Classification and Routing" (DELEGATE,
MOUNT_INNER_REGISTERED), DD-11, DD-12, I006, EVP-1 dm-0 expectation).
Generated 2026-10-08 by the acceptance-test-generator. Budget used: 3/3
integration for the feature "registration wins over Dolphin" (AC-060).

Test boundary: FakeRunner for lsblk, findmnt, systemctl, probe, mount; real
sysfs, registry, records and locks under HostPaths(root=tmp_path).

This flow uses the real capture fixtures/deck/lsblk-columns-tree.json as-is:
dm-0 is the udisks mapping of sdb1 (PERSONAL's container) with a label-derived
name, which fixtures/deck/udev-dm-0.txt shows. EVP-1 expects the dm-0 auto
instance to DELEGATE to the registered unit named below.

Fixtures expected from tests/conftest.py: fake_runner, fake_platform, host_tree,
fake_kmsg, fake_clock, ctx. Skipped until steamos_mounter.reconcile exists.
"""

from pathlib import Path

import pytest

reconcile = pytest.importorskip("steamos_mounter.reconcile")
state = pytest.importorskip("steamos_mounter.state")

PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
PERSONAL_DEVICE_PATH = f"/dev/disk/by-uuid/{PERSONAL_UUID}"
PERSONAL_RECORD = f"run/steamos-mounter/records/registered/{PERSONAL_UUID}.json"
PERSONAL_INSTANCE = (
    "dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52\\x2da297\\x2d31643c64724d"
)
REGISTERED_UNIT = f"steamos-mounter@{PERSONAL_INSTANCE}.service"
DM0_SYSPATH = "/sys/devices/virtual/block/dm-0"
DM0_RECORD = "run/steamos-mounter/records/auto/dm-0-252_0.json"
CLI_ROOT = "sudo /opt/steamos-mounter/bin/steamos-mounter"
ABSENT_NEXT_STEP = CLI_ROOT + " mount --device /dev/sdb1"
ELSEWHERE_NEXT_STEP = (
    "Unmount it there, then " + CLI_ROOT + " mount --volume PERSONAL to use the "
    "fixed path."
)


@pytest.fixture
def systemctl_show_active() -> str:
    """systemctl show answer for an active registered instance."""
    return "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\n"


@pytest.fixture
def systemctl_show_inactive() -> str:
    """systemctl show answer for a registered instance that never ran."""
    return "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\n"


# AC-060: "Given a registered BitLocker volume that the owner unlocked in
#   Dolphin ..., then there is no grace period. As soon as the unlocked inner
#   device appears, the tool mounts it at the registered fixed path, not under
#   the auto-mount path, because the registration wins."
# AC-059 (only the fixed path), EVP-1 (dm-0 -> DELEGATE to the registered unit)
# ROI: 40 (BV:8 x Freq:4 + Legal:0 + Defect:8)
# Behavior: dm-0 add -> dm instance DELEGATE to REGISTERED_UNIT (container UUID
#   registered) -> request_reconcile "reloaded" -> registered RELOAD routes
#   MOUNT_INNER_REGISTERED -> chain on /dev/dm-0 at /run/media/deck/PERSONAL
# @category: core-functionality
# @dependency: reconcile, routing, systemd, escape, mounter, ntfs, mounts,
#   state, locks
# @complexity: high
# @real-dependency: tmp_path sysfs (dm-0 slaves/, dm/name), records, flock
def test_dm0_udisks_mapping_delegates_to_registered_fixed_path(
    tmp_path: Path,
) -> None:
    """Design Doc "Dolphin-unlock Path", registered branch.

    Given
      - HostPaths(root=tmp_path): registry with MEDIABOX and PERSONAL; by-uuid
        link for PERSONAL -> ../../sdb1; sysfs: /sys/class/block/dm-0/slaves/
        sdb1, /sys/block/dm-0/dm/name = the udisks name from udev-dm-0.txt,
        /sys/class/block/sdb1/holders/dm-0; no record for PERSONAL yet
      - FakeRunner script:
        lsblk ... -> fixtures/deck/lsblk-columns-tree.json
        systemctl show -p ... <REGISTERED_UNIT> -> systemctl_show_active
        systemctl reload --no-block <REGISTERED_UNIT> -> rc 0
        findmnt ... --list --real -> fixtures/deck/findmnt-real-list.json
            (no /dev/dm-0 entry)
        ntfs-3g.probe --readwrite /dev/dm-0 -> rc 0
        mount -i -t ntfs3 -o ... /dev/dm-0 /run/media/deck/PERSONAL -> rc 0
        findmnt ... --mountpoint /run/media/deck/PERSONAL
            -> fixtures/synthetic/findmnt-personal-ntfs3-rw.json
    When
      - reconcile.run(ctx, InstanceKind.AUTO, DM0_SYSPATH, Trigger.START)
      - reconcile.run(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH,
        Trigger.RELOAD)
    Then (pass criteria)
      - first outcome: route.action == Action.DELEGATE, route.delegate_unit ==
        REGISTERED_UNIT (never an auto unit); request_reconcile "reloaded";
        no record at tmp_path/DM0_RECORD; no mount call from this pass
      - second outcome: route.action == Action.MOUNT_INNER_REGISTERED, state
        MountedRW, mount.target PERSONAL_PATH, mount.device "/dev/dm-0";
        record mapping.opened_by "other" and mapping.name == the udisks name
      - no argv anywhere contains a path under /run/media/deck other than
        PERSONAL_PATH (AC-059); no cryptsetup call; no key unit start
      - a delegated RELOAD never starts the key unit even though no stored key
        exists (ADR-0005 D1.3): no "systemctl start" in the log at all
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")


# I006 / D006 (Design Doc "Runtime State Records", "Delegation to an inactive
#   instance"): "a delegating dm-* instance whose request_reconcile returned
#   absent writes a minimal auto record under its own key, with state
#   NotMounted, reason no_partition_instance and next step
#   <cli> mount --device /dev/<container>, so list shows the unlocked-but-
#   unmounted volume instead of nothing."
# AC-060 (SM-15 last bullet), AC-040 (list state), DD-22 (NotMounted)
# ROI: 26 (BV:6 x Freq:3 + Legal:0 + Defect:8)
# Behavior: registered instance inactive -> request_reconcile "absent", WARNING,
#   no start -> dm-0 writes the minimal record -> compute_views shows it
# @category: edge-case
# @dependency: reconcile, routing, systemd, state
# @complexity: medium
# @real-dependency: tmp_path records
def test_delegate_absent_writes_not_mounted_record_shown_by_list(
    tmp_path: Path,
) -> None:
    """Dolphin unlock while the registered instance is inactive is visible.

    Given
      - the setup of the test above, but systemctl show <REGISTERED_UNIT> ->
        systemctl_show_inactive
    When
      - reconcile.run(ctx, InstanceKind.AUTO, DM0_SYSPATH, Trigger.START)
      - views = state.compute_views(ctx, registry, tree, table) with the same
        tree and the findmnt list (what list renders, AC-067: no writes)
    Then (pass criteria)
      - request_reconcile result "absent"; the log holds the systemctl show and
        no systemctl start or reload (D006: never start what the owner or
        systemd stopped); caplog has one WARNING "no partition instance"
      - tmp_path/DM0_RECORD exists with kind "auto", key "dm-0-252_0", state
        "NotMounted", reason "no_partition_instance", next_step ==
        ABSENT_NEXT_STEP, mapping and mount describing nothing mounted
      - views contains an entry for the dm-0 record with state
        VolumeState.NOT_MOUNTED, words "present, not mounted yet" and the next
        step above; compute_views wrote no file (directory listing unchanged)
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")


# AC-060 continued: "If udisks or Dolphin mounted it first, the tool doesn't
#   fight it (AC-034): list records it as mounted elsewhere and shows where."
# ROI: 28 (BV:6 x Freq:3 + Legal:0 + Defect:8)
# Behavior: findmnt list shows /dev/dm-0 at udisks' target -> held check ->
#   MountedElsewhere (at PATH), no mount, next step to unmount there
# @category: edge-case
# @dependency: reconcile, mounts, state
# @complexity: medium
# @real-dependency: tmp_path records, flock
def test_udisks_mounted_first_is_recorded_mounted_elsewhere(
    tmp_path: Path,
) -> None:
    """Held check reports where Dolphin mounted PERSONAL's inner filesystem.

    Given
      - the setup of the first test, with findmnt ... --list --real ->
        fixtures/synthetic/findmnt-list-dm0-at-udisks-path.json listing
        /dev/dm-0 (252:0) at /run/media/deck/PERSONAL1 (udisks appends a digit
        when /run/media/deck/PERSONAL already exists as the fixed-path leaf)
    When
      - reconcile.run(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH,
        Trigger.RELOAD)
    Then (pass criteria)
      - outcome.state == VolumeState.MOUNTED_ELSEWHERE; no probe, mount or
        ntfs-3g call; record state "MountedElsewhere" with the udisks target
      - state.words(...) == "mounted elsewhere (at /run/media/deck/PERSONAL1)"
        and next_step == ELSEWHERE_NEXT_STEP (AC-040)
      - no notification (not in the notify list), one NOTICE in caplog (AC-034)
    Design edge to confirm with the designer before implementing: when udisks
    picks the fixed path itself (inner label PERSONAL and no leaf directory
    yet), the held check reads "mounted at its own target" and reports
    "already mounted" although this tool did not mount it. Decide whether that
    case is MountedElsewhere or an owned MountedRW, and add the variant here.
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")
