"""Unregistered dirty NTFS partition auto-mount flow - integration skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "Device
Classification and Routing", "NTFS Chain, Mount Options and Read-back",
"Notifications"). Generated 2026-10-08 by the acceptance-test-generator.
Budget used: 2/3 integration for the feature "auto-mount" (FR-05, FR-07),
shared with test_flow_unregistered_exfat.

Test boundary: FakeRunner for every command; FakeKernelLog for /dev/kmsg; real
files, locks and records under HostPaths(root=tmp_path).

Synthetic tree: fixtures/synthetic/lsblk-tree-with-ntfs-sdc1.json (first line
"# synthetic: real tree plus removable disk sdc, HOTPLUG true, with sdc1 ntfs
label MOVIES uuid 2AB4C1D5E6F70819 MAJ:MIN 8:33").

Fixtures expected from tests/conftest.py: fake_runner, fake_platform, host_tree,
fake_kmsg, fake_clock, ctx. Skipped until steamos_mounter.reconcile exists.
"""

import logging
import stat
from pathlib import Path

import pytest
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import (
    MOUNT,
    NTFS3G,
    PROBE,
    SETFACL,
    SYSTEMD_RUN,
    TABLE_ARGV,
    known_os_set,
    make_mount_base,
    make_var_run,
    read_record,
    readback_argv,
    runtime_dirs,
    script_desktop_session,
    script_lsblk,
    script_notify,
    sm_fields,
    write_registry,
)
from tests.helpers.host_tree import SysfsDevice

from steamos_mounter.model import InstanceKind, Trigger, VolumeState

reconcile = pytest.importorskip("steamos_mounter.reconcile")
ntfs = pytest.importorskip("steamos_mounter.ntfs")

MOVIES_PATH = "/run/media/deck/MOVIES"
SDC1_SYSPATH = (
    "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-2/2-2:1.0/host1/"
    "target1:0:0/1:0:0:0/block/sdc/sdc1"
)
SDC1_RECORD = "run/steamos-mounter/records/auto/sdc1-8_33.json"
NTFS_RW_OPTIONS = "nosuid,nodev,uid=1000,gid=1000,umask=0022,windows_names"
KMSG_DIRTY_LINE = 'ntfs3(sdc1): volume is dirty and "force" flag is not set!'
DIRTY_WARNING = (
    "MOVIES is dirty: Windows did not close it cleanly. It is mounted read-write"
    " with ntfs-3g."
)


# AC-022: "Given an unregistered dirty NTFS partition, then it goes through the
#   FR-04 chain with the same warnings."
# AC-016 (chain outcome), AC-046 (notification), AC-027 (safe auto name)
# ROI: 49 (BV:7 x Freq:6 + Legal:0 + Defect:7)
# Behavior: auto instance for sdc1 -> AUTO_MOUNT at /run/media/deck/MOVIES ->
#   probe 15 -> ntfs3 refused (kmsg) -> ntfs-3g mounted -> MountedRWDirty, dirty
#   warning in journal, record and notification, same texts as the registered path
# @category: core-functionality
# @dependency: reconcile, routing, naming, ntfs, mounter, kmsg, mounts, state,
#   locks, session, notify
# @complexity: high
# @real-dependency: tmp_path files, flock (holo lock for sdc1 + volume lock)
def test_unregistered_dirty_ntfs_uses_chain_and_warns(
    tmp_path: Path, ctx, host_tree, fake_runner, fake_kmsg, caplog
) -> None:
    """The auto path runs the same chain and reports the same way as registered.

    Given
      - HostPaths(root=tmp_path): empty registry (no config.toml), OS set known
        from the rules fixture, /run/media/deck present as 0750 (left untouched,
        AC-024 "never changed when present"), sysfs for sdc1.
      - FakeRunner script:
        lsblk ... -> fixtures/synthetic/lsblk-tree-with-ntfs-sdc1.json
        findmnt ... --list --real -> fixtures/deck/findmnt-real-list.json
        ntfs-3g.probe --readwrite /dev/sdc1 -> rc 15
        mount -i -t ntfs3 -o <NTFS_RW_OPTIONS> /dev/sdc1 /run/media/deck/MOVIES
            -> rc 32; FakeKernelLog yields KMSG_DIRTY_LINE after the mark
        findmnt ... --mountpoint /run/media/deck/MOVIES
            -> rc 1 empty, then fixtures/synthetic/findmnt-movies-fuseblk-rw.json
        ntfs-3g -o <NTFS_RW_OPTIONS> /dev/sdc1 /run/media/deck/MOVIES -> rc 0
        loginctl ... -> Desktop verdict (fixtures/deck/loginctl-*.txt)
        systemd-run --user ... notify-send ... -> rc 0
    When
      - reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.START)
    Then (pass criteria)
      - outcome.state == VolumeState.MOUNTED_RW_DIRTY, reason "dirty"
      - the chain argv sequence is probe, ntfs3 mount, ntfs-3g, exactly as in
        the registered flow but with /dev/sdc1 and MOVIES_PATH; the default
        chain is used (ntfs3 rw, then ntfs-3g rw) since no registry entry
        exists
      - record tmp_path/SDC1_RECORD: kind "auto", name "MOVIES", state
        "MountedRWDirty", mount.driver "ntfs-3g", attempt.probe code 15 dirty,
        attempt.steps [ntfs3 refused with detail = the kmsg line without the
        ntfs3(<kname>): prefix (Record Schema example), ntfs-3g mounted],
        warning "MOVIES is dirty: Windows did not close it cleanly. It is
        mounted read-write with ntfs-3g.", next_step "Run chkdsk /f on it in
        Windows."
      - one notify-send call with summary "MOVIES is dirty" and the same body
        shape as the registered flow (AC-046)
      - caplog holds exactly one WARNING containing "dirty" with
        SM_EVENT=reconcile and SM_VOLUME=MOVIES (AC-041)
      - /run/media/deck under tmp_path keeps mode 0750 and no setfacl call is
        made (base already present)
    """
    caplog.set_level(logging.DEBUG)
    runtime_dirs(ctx)
    write_registry(tmp_path, None)
    known_os_set(tmp_path)
    base = make_mount_base(tmp_path)
    make_var_run(tmp_path)
    host_tree.add_block(SysfsDevice(kname="sdc", devnum="8:32"))
    host_tree.add_block(
        SysfsDevice(kname="sdc1", devnum="8:33", parent="sdc", syspath=SDC1_SYSPATH)
    )
    script_lsblk(fake_runner, "lsblk-tree-with-ntfs-sdc1.json")
    fake_runner.on(TABLE_ARGV, "findmnt-real-list.json")
    fake_runner.on(PROBE, Answer(returncode=15))
    fake_runner.on(MOUNT, Answer(returncode=32))
    fake_runner.on(
        readback_argv(MOVIES_PATH),
        "findmnt-sdb5-not-mounted.json",
        Answer.from_fixture("findmnt-movies-fuseblk-rw.json", returncode=0),
    )
    fake_runner.on(NTFS3G, Answer())
    script_desktop_session(fake_runner)
    script_notify(fake_runner)
    fake_kmsg.queue(KMSG_DIRTY_LINE)

    outcome = reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.START)

    assert (outcome.state, outcome.reason) == (VolumeState.MOUNTED_RW_DIRTY, "dirty")
    chain = [argv for argv in fake_runner.argvs if argv[0] in {PROBE, MOUNT, NTFS3G}]
    assert chain == [
        (PROBE, "--readwrite", "/dev/sdc1"),
        (MOUNT, "-i", "-t", "ntfs3", "-o", NTFS_RW_OPTIONS, "/dev/sdc1", MOVIES_PATH),
        (NTFS3G, "-o", NTFS_RW_OPTIONS, "/dev/sdc1", MOVIES_PATH),
    ]
    record = read_record(tmp_path, SDC1_RECORD)
    tried = [(step["driver"], step["mode"]) for step in record["attempt"]["steps"]]
    assert tried == [("ntfs3", "rw"), ("ntfs-3g", "rw")]  # default chain
    assert (record["kind"], record["name"], record["state"]) == (
        "auto",
        "MOVIES",
        "MountedRWDirty",
    )
    assert record["mount"]["driver"] == "ntfs-3g"
    assert record["attempt"]["probe"] == {"code": 15, "class": "dirty"}
    assert [step["result"] for step in record["attempt"]["steps"]] == [
        "refused",
        "mounted",
    ]
    assert record["attempt"]["steps"][0]["detail"] == KMSG_DIRTY_LINE.removeprefix(
        "ntfs3(sdc1): "
    )
    assert record["warning"] == DIRTY_WARNING
    assert record["next_step"] == "Run chkdsk /f on it in Windows."
    [notification] = [argv for argv in fake_runner.argvs if argv[0] == SYSTEMD_RUN]
    assert notification[-2:] == (
        "MOVIES is dirty",
        "Mounted read-write with ntfs-3g at /run/media/deck/MOVIES. Run chkdsk /f"
        " on it in Windows.",
    )
    dirty_warnings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING
        and "dirty" in r.getMessage()
        and sm_fields(r).get("SM_EVENT") == "reconcile"
        and sm_fields(r).get("SM_VOLUME") == "MOVIES"
    ]
    assert len(dirty_warnings) == 1
    assert stat.S_IMODE(base.stat().st_mode) == 0o750
    assert all(argv[0] != SETFACL for argv in fake_runner.argvs)
