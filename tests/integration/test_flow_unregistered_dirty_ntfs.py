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

from pathlib import Path

import pytest

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
def test_unregistered_dirty_ntfs_uses_chain_and_warns(tmp_path: Path) -> None:
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
        chain is used (ntfs.DEFAULT_CHAIN) since no registry entry exists
      - record tmp_path/SDC1_RECORD: kind "auto", name "MOVIES", state
        "MountedRWDirty", mount.driver "ntfs-3g", attempt.probe code 15 dirty,
        attempt.steps [ntfs3 refused KMSG_DIRTY_LINE, ntfs-3g mounted],
        warning "MOVIES is dirty: Windows did not close it cleanly. It is
        mounted read-write with ntfs-3g.", next_step "Run chkdsk /f on it in
        Windows."
      - one notify-send call with summary "MOVIES is dirty" and the same body
        shape as the registered flow (AC-046)
      - /run/media/deck under tmp_path keeps mode 0750 and no setfacl call is
        made (base already present)
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")
