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

import logging
from pathlib import Path

import pytest
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import (
    ACTIVE,
    CRYPTSETUP,
    DMSETUP,
    LOGINCTL,
    MOUNT,
    NTFS3G,
    PROBE,
    SYSTEMCTL,
    SYSTEMD_RUN,
    TABLE_ARGV,
    known_os_set,
    make_mount_base,
    make_var_run,
    read_record,
    readback_argv,
    runtime_dirs,
    script_lsblk,
    sm_fields,
    write_registry,
)
from tests.helpers.host_tree import SysfsDevice

from steamos_mounter import blockdev, config, mounts
from steamos_mounter.journal import NOTICE
from steamos_mounter.model import InstanceKind, Trigger, VolumeState
from steamos_mounter.routing import Action

reconcile = pytest.importorskip("steamos_mounter.reconcile")
systemd = pytest.importorskip("steamos_mounter.systemd")
escape = pytest.importorskip("steamos_mounter.escape")
state = pytest.importorskip("steamos_mounter.state")

OBAMA_PATH = "/run/media/deck/OBAMA"
DM1_SYSPATH = "/sys/devices/virtual/block/dm-1"
SDC1_SYSPATH = (
    "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-2/2-2:1.0/host1/"
    "target1:0:0/1:0:0:0/block/sdc/sdc1"
)
SDC1_RECORD = "run/steamos-mounter/records/auto/sdc1-8_33.json"
DM1_RECORD = "run/steamos-mounter/records/auto/dm-1-252_1.json"
NTFS_RW_OPTIONS = "nosuid,nodev,uid=1000,gid=1000,umask=0022,windows_names"
CLI = "sudo /opt/steamos-mounter/bin/steamos-mounter"
# A label-derived udisks name, the same shape as DM_NAME in udev-dm-0.txt.
UDISKS_NAME = "OBAMA_BACKUP_1_2_2025"


def given_obama_unlocked_in_dolphin(ctx, tmp_path: Path, host_tree) -> None:
    """Empty registry, OS set known, base present, sysfs for sdc, sdc1 and dm-1."""
    runtime_dirs(ctx)
    write_registry(tmp_path, None)
    known_os_set(tmp_path)
    make_mount_base(tmp_path)
    make_var_run(tmp_path)
    host_tree.add_block(SysfsDevice(kname="sdc", devnum="8:32"))
    host_tree.add_block(
        SysfsDevice(
            kname="sdc1",
            devnum="8:33",
            parent="sdc",
            syspath=SDC1_SYSPATH,
            holders=("dm-1",),
        )
    )
    host_tree.add_block(
        SysfsDevice(
            kname="dm-1",
            devnum="252:1",
            syspath=DM1_SYSPATH,
            slaves=("sdc1",),
            dm_name=UDISKS_NAME,
        )
    )


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
    tmp_path: Path, ctx, host_tree, fake_runner, partition_auto_unit
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
    given_obama_unlocked_in_dolphin(ctx, tmp_path, host_tree)
    script_lsblk(fake_runner, "lsblk-tree-dolphin-unregistered.json")
    fake_runner.on((SYSTEMCTL, "show"), Answer(stdout=ACTIVE.encode()))
    fake_runner.on((SYSTEMCTL, "reload", "--no-block"), Answer())
    fake_runner.on(TABLE_ARGV, "findmnt-real-list.json")
    fake_runner.on(PROBE, Answer())
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(
        readback_argv(OBAMA_PATH),
        Answer.from_fixture("findmnt-obama-ntfs3-rw.json", returncode=0),
    )

    first = reconcile.run(ctx, InstanceKind.AUTO, DM1_SYSPATH, Trigger.START)
    second = reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.RELOAD)

    assert first.route.action is Action.DELEGATE
    assert first.route.delegate_unit == partition_auto_unit
    assert first.reason == "reloaded"  # what systemd.request_reconcile returned
    systemctl = [argv[1:3] for argv in fake_runner.argvs if argv[0] == SYSTEMCTL]
    assert systemctl == [
        ("show", "--property=LoadState,ActiveState"),
        ("reload", "--no-block"),
    ]
    assert not (tmp_path / DM1_RECORD).exists()  # delegating instances own nothing
    assert second.route.action is Action.AUTO_MOUNT_INNER
    assert second.state is VolumeState.MOUNTED_RW
    record = read_record(tmp_path, SDC1_RECORD)
    assert (record["mount"]["device"], record["mount"]["target"]) == (
        "/dev/dm-1",
        OBAMA_PATH,
    )
    assert record["name"] == "OBAMA"  # the inner label, never the dm name
    assert [argv for argv in fake_runner.argvs if argv[0] == MOUNT] == [
        (MOUNT, "-i", "-t", "ntfs3", "-o", NTFS_RW_OPTIONS, "/dev/dm-1", OBAMA_PATH)
    ]
    tools = {argv[0] for argv in fake_runner.argvs}
    assert {CRYPTSETUP, DMSETUP}.isdisjoint(tools)  # Dolphin did the unlock
    assert record["mapping"] == {
        "name": UDISKS_NAME,
        "kname": "dm-1",
        "devnum": "252:1",
        "opened_by": "other",
        "key_unit_invocation_id": None,
        "save_pending": False,
    }
    assert (record["source"]["kname"], record["source"]["devnum"]) == ("sdc1", "8:33")
    assert not any(
        "steamos-mounter-key@" in " ".join(argv) for argv in fake_runner.argvs
    )


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
    tmp_path: Path, ctx, host_tree, fake_runner, caplog
) -> None:
    """Held check wins over the chain when udisks got there first.

    Given
      - the same tree and sysfs as the test above
      - FakeRunner: findmnt ... --list --real ->
        fixtures/synthetic/findmnt-list-dm1-at-udisks-path.json, which lists
        /dev/dm-1 (MAJ:MIN 252:1) mounted at /run/media/deck/OBAMA by udisks;
        scripted twice, once for reconcile and once for compute_views, so a
        second table read inside reconcile fails the test
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
      - state.compute_views(...) shows the auto entry as mounted elsewhere with
        path /run/media/deck/OBAMA, i.e. "mounted elsewhere (at
        /run/media/deck/OBAMA)" once the renderer adds "(at PATH)"
    """
    caplog.set_level(logging.DEBUG)
    given_obama_unlocked_in_dolphin(ctx, tmp_path, host_tree)
    script_lsblk(fake_runner, "lsblk-tree-dolphin-unregistered.json")
    udisks_table = Answer.from_fixture(
        "findmnt-list-dm1-at-udisks-path.json", returncode=0
    )
    # One table read for reconcile's held check, one for compute_views below.
    fake_runner.on(TABLE_ARGV, udisks_table, udisks_table)

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.RELOAD)

    assert outcome.state is VolumeState.MOUNTED_ELSEWHERE
    assert OBAMA_PATH in outcome.reason
    tools = {argv[0] for argv in fake_runner.argvs}
    assert {PROBE, MOUNT, NTFS3G}.isdisjoint(tools)
    record = read_record(tmp_path, SDC1_RECORD)
    assert record["state"] == "MountedElsewhere"
    assert record["mount"] is None  # nothing mounted by this tool, no created_dir
    # state.next_step's MountedElsewhere step, in the auto form (--device).
    assert record["next_step"] == (
        f"Unmount it there, then run {CLI} mount --device /dev/sdc1 to use the"
        " fixed path."
    )
    [notice] = [
        r
        for r in caplog.records
        if r.levelno == NOTICE
        and sm_fields(r).get("SM_EVENT") == "reconcile"
        and sm_fields(r).get("SM_STATE") == "MountedElsewhere"
    ]
    assert OBAMA_PATH in sm_fields(notice)["SM_REASON"]
    assert {LOGINCTL, SYSTEMD_RUN}.isdisjoint(tools)  # not in the notify list
    views = state.compute_views(
        ctx, config.load(ctx), blockdev.read_tree(ctx), mounts.table(ctx)
    )
    [obama] = [view for view in views if view.kind is InstanceKind.AUTO]
    assert (obama.state, obama.path) == (VolumeState.MOUNTED_ELSEWHERE, OBAMA_PATH)
    # state.words gives the state; the renderer appends "(at PATH)" (state._WORDS).
    rendered = f"{state.words(obama.state, obama.reason)} (at {obama.path})"
    assert rendered == "mounted elsewhere (at /run/media/deck/OBAMA)"
