"""Unregistered exFAT stick (GAMES) auto-mount flow - integration skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "Unregistered
Plug-in (exFAT stick GAMES)", "Device Classification and Routing", "Mount
Options per Driver", "Names and Paths"). Generated 2026-10-08 by the
acceptance-test-generator. Budget used: 2/3 integration for the feature
"auto-mount" (FR-05, FR-07): this module and test_flow_unregistered_dirty_ntfs.

Test boundary: FakeRunner for every command; real files, locks and records under
HostPaths(root=tmp_path); no /dev/kmsg use for exfat (no NTFS chain).

The real Deck tree (fixtures/deck/lsblk-columns-tree.json) holds no exFAT stick,
so this flow uses a synthetic tree derived from it:
fixtures/synthetic/lsblk-tree-with-exfat-sdc1.json (first line
"# synthetic: real tree plus removable disk sdc, HOTPLUG true, with sdc1 exfat
label GAMES uuid 1234-ABCD MAJ:MIN 8:33"). Keep the real entries untouched so
routing still sees the OS partitions and the registered UUIDs.

Fixtures expected from tests/conftest.py: fake_runner, fake_platform, host_tree,
fake_clock, ctx. Skipped until steamos_mounter.reconcile exists.
"""

from pathlib import Path

import pytest

reconcile = pytest.importorskip("steamos_mounter.reconcile")
mounter = pytest.importorskip("steamos_mounter.mounter")

REPO = Path(__file__).resolve().parents[2]
SYNTHETIC = REPO / "tests" / "fixtures" / "synthetic"

GAMES_PATH = "/run/media/deck/GAMES"
# Illustrative; build the real one from the synthetic tree's PATH/PKNAME fields.
SDC1_SYSPATH = (
    "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-2/2-2:1.0/host1/"
    "target1:0:0/1:0:0:0/block/sdc/sdc1"
)
SDC1_RECORD = "run/steamos-mounter/records/auto/sdc1-8_33.json"
EXFAT_OPTIONS = (
    "nosuid,nodev,uid=1000,gid=1000,umask=0022,iocharset=utf8,errors=remount-ro"
)


@pytest.fixture
def expected_mount_argv() -> tuple[str, ...]:
    """The single exfat step (Design Doc "Step Invocation", "Mount Options")."""
    return (
        "/usr/bin/mount",
        "-i",
        "-t",
        "exfat",
        "-o",
        EXFAT_OPTIONS,
        "/dev/sdc1",
        GAMES_PATH,
    )


# AC-021: "Given an unregistered exFAT or FAT stick labeled GAMES, when it is
#   plugged in, then it is mounted at /run/media/deck/GAMES with nosuid,nodev
#   within the latency target."
# AC-024: "Given /run/media/deck is missing, then it is created as root with mode
#   0750 and an ACL of u:deck:r-x (the same as udisks) before anything is
#   mounted under it."
# AC-079: "... findmnt shows nosuid,nodev and no noexec."
# AC-036: uid=1000,gid=1000,umask=0022 so deck can write without sudo
# ROI: 71 (BV:8 x Freq:8 + Legal:0 + Defect:7)
# Behavior: SYSTEMD_WANTS starts the auto instance for sdc1 -> route AUTO_MOUNT
#   (not registered, not OS, removable through sdc HOTPLUG) -> base created with
#   ACL -> holo lock -> one exfat step -> findmnt read-back -> MountedRW recorded
# @category: core-functionality
# @dependency: reconcile, routing, naming, mounter, mounts, blockdev, config,
#   state, locks
# @complexity: medium
# @real-dependency: tmp_path /run/media (created by the flow), flock (holo lock
#   /var/run/jupiter-automount-sdc1.lock and locks/volume-1234-abcd.lock), record
def test_unregistered_exfat_games_mounts_with_nosuid_nodev(tmp_path: Path) -> None:
    """Design Doc "Unregistered Plug-in (exFAT stick GAMES)" end to end.

    Given
      - HostPaths(root=tmp_path): /etc/steamos-mounter exists (good owner and
        mode) with no config.toml (absent file = empty registry, I001);
        /dev/disk/by-partsets/all/ links and
        /run/udev/rules.d/90-holo-partsets-all.rules from
        fixtures/deck/udev-run-90-holo-partsets-all.rules.txt (OS set known);
        no /run/media at all; sysfs for sdc/sdc1 from the synthetic tree.
      - FakeRunner script:
        lsblk ... -> fixtures/synthetic/lsblk-tree-with-exfat-sdc1.json
        findmnt ... --list --real -> fixtures/deck/findmnt-real-list.json
        setfacl -m u:1000:r-x /run/media/deck -> rc 0
        mount -i -t exfat -o <EXFAT_OPTIONS> /dev/sdc1 /run/media/deck/GAMES
            -> rc 0
        findmnt ... --mountpoint /run/media/deck/GAMES
            -> fixtures/synthetic/findmnt-games-exfat-rw.json (rc 0; options
               include nosuid,nodev; no noexec)
    When
      - reconcile.run(ctx, InstanceKind.AUTO, SDC1_SYSPATH, Trigger.START)
    Then (pass criteria)
      - outcome.route.action == Action.AUTO_MOUNT and outcome.state ==
        VolumeState.MOUNTED_RW with no warning
      - tmp_path/run/media has mode 0755 and tmp_path/run/media/deck has mode
        0750, both created before the mount call; the setfacl call precedes the
        mount call in the FakeRunner log (AC-024)
      - exactly one mount call, equal to expected_mount_argv; no ntfs-3g.probe,
        ntfs-3g or cryptsetup call; "noexec" appears in no argv (AC-079)
      - the mount target is a direct child of /run/media/deck named GAMES
        (naming.sanitize_label("GAMES") == "GAMES", AC-027)
      - tmp_path/var/run/jupiter-automount-sdc1.lock exists (holo lock, kname
        matches ^[a-z0-9]+$)
      - record tmp_path/SDC1_RECORD: kind "auto", key "sdc1-8_33", name "GAMES",
        state "MountedRW", mount.driver "exfat", mount.mode "rw",
        mount.created_dir true, mapping null
      - no loginctl, systemd-run or notify-send call (healthy state: no
        notification, Design Doc "Notifications" 1)
      - state.compute_views(...) lists GAMES after the registered volumes with
        words "mounted read-write" and next step "-" (AC-040)
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")
