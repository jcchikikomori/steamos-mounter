"""Install, re-install, uninstall over a tmp HostPaths root - integration skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "Python install
(Install Equals Update)", "Python uninstall (Unwire First, Then Stop)", "Install
Manifest (Authoritative)", "Install, Update and Uninstall" diagram, ADR-0004
D7, D8.6). Generated 2026-10-08 by the acceptance-test-generator. Budget used:
3/3 integration for the feature "update-proof install and uninstall" (FR-11,
FR-19).

Test boundary: FakeRunner for systemctl (daemon-reload, show, start, stop),
udevadm control --reload, setfacl and lsblk; every file operation is real under
HostPaths(root=tmp_path) with trusted_uid = the test uid, so owner, mode,
symlink flips and atomic writes are exercised for real. The release tree is
staged under tmp_path/opt/steamos-mounter/releases/<release>/ from the
repository (bin/, data/, src -> lib/, README.md) with the modes install.sh would
set (dirs 0755, files 0644, bin/steamos-mounter 0755, no symlinks).

The "--release equals the running entry point's release root" rule is satisfied
through whatever the implementation exposes for tests (a ctx attribute or an
installer parameter); note it here when implementing.

Skipped until steamos_mounter.installer exists.
"""

from pathlib import Path

import pytest

installer = pytest.importorskip("steamos_mounter.installer")
manifest = pytest.importorskip("steamos_mounter.manifest")
config = pytest.importorskip("steamos_mounter.config")

REPO = Path(__file__).resolve().parents[2]
RELEASE_NAME = "0.1.0-20261008T000000Z"
OPT = "opt/steamos-mounter"
RELEASE_DIR = f"{OPT}/releases/{RELEASE_NAME}"
REGISTRY = "etc/steamos-mounter/config.toml"
KEPT_REGISTRY = "var/lib/steamos-mounter/kept-config.toml"
KEYS_DIR = "var/lib/steamos-mounter/keys"
MEDIABOX_KEY = f"{KEYS_DIR}/01D95F1575592A30.key"
ETC_FILES = (
    "etc/atomic-update.conf.d/steamos-mounter.conf",
    "etc/systemd/system/steamos-mounter@.service",
    "etc/systemd/system/steamos-mounter-auto@.service",
    "etc/systemd/system/steamos-mounter-key@.service",
    "etc/udev/rules.d/90-steamos-mounter.rules",
)
MEDIABOX_LINK = (
    "etc/systemd/system/dev-disk-by\\x2duuid-01D95F1575592A30.device.wants/"
    "steamos-mounter@dev-disk-by\\x2duuid-01D95F1575592A30.service"
)


@pytest.fixture
def staged_release(tmp_path: Path) -> Path:
    """Stage the repository as a root-owned-looking release under tmp_path.

    Copies REPO/bin, REPO/data, REPO/README.md and REPO/src/steamos_mounter (as
    lib/steamos_mounter) into tmp_path/RELEASE_DIR with the install.sh modes;
    __pycache__ directories are dropped. Returns the release path.
    """
    pytest.skip("skeleton fixture: build with shutil.copytree + os.chmod")


# AC-037: "Given sudo ./install.sh, then code is in root-owned
#   /opt/steamos-mounter/, and the keep-list drop-in, systemd units and udev rule
#   are installed. Running it a second time leaves the same files, no duplicate
#   wiring, and the existing config and keys untouched."
# AC-039: "Given an install, then nothing under /opt/steamos-mounter/ is writable
#   by deck."
# ROI: 71 (BV:9 x Freq:7 + Legal:0 + Defect:8)
# Behavior: install -> manifest dirs, current flip, /etc files, links, reloads,
#   start inactive instances, mount base, prune -> second install: every file
#   step "skipped", tree identical, config and key bytes and mtimes unchanged
# @category: core-functionality
# @dependency: installer, manifest, wiring, config, atomicfile, state, systemd
# @complexity: high
# @real-dependency: tmp_path tree (modes, owners, symlinks, atomic writes)
def test_install_twice_leaves_identical_tree_and_untouched_config(
    tmp_path: Path,
    staged_release: Path,
) -> None:
    """Install equals update: the second run changes nothing.

    Given
      - HostPaths(root=tmp_path) holding staged_release, a pre-existing
        tmp_path/REGISTRY with one MEDIABOX entry (0644) and tmp_path/
        MEDIABOX_KEY (0600 in a 0700 dir), both owned by the test uid; no
        /run/steamos-mounter tree yet; no /run/media
      - FakeRunner script: systemctl daemon-reload -> 0; udevadm control
        --reload -> 0; lsblk ... -> fixtures/deck/lsblk-columns-tree.json;
        systemctl show ... -> ActiveState=inactive for every instance;
        systemctl start --no-block <unit> -> 0; setfacl ... -> 0
    When
      - first = installer.install(ctx, release=tmp_path/RELEASE_DIR)
      - snapshot = {relative path: (type, mode, owner, link target or sha256)}
        over tmp_path, excluding __pycache__
      - second = installer.install(ctx, release=tmp_path/RELEASE_DIR)
    Then (pass criteria)
      - first.exit_code == ExitCode.OK and every line status is "ok" or
        "skipped"; tmp_path/OPT/current -> f"releases/{RELEASE_NAME}" and
        tmp_path/OPT/bin -> "current/bin"
      - every ETC_FILES path exists with mode 0644 and content equal to the
        release copy; tmp_path/MEDIABOX_LINK is a symlink to
        /etc/systemd/system/steamos-mounter@.service and is the only entry in
        its .device.wants directory
      - the five /run/steamos-mounter rows of the manifest exist with the
        manifest modes (0755, 0755, 0755, 0755, 0700) (D002)
      - the second snapshot equals the first; the "write" steps of the second
        report are "skipped"; REGISTRY and MEDIABOX_KEY keep their bytes, mode
        and st_mtime_ns
      - no path under tmp_path/OPT has a group or other write bit, and none is
        a symlink except current and bin (AC-039)
      - the FakeRunner log holds, per run, one daemon-reload after the links
        and one udevadm control --reload; one systemctl start --no-block for
        MEDIABOX's registered instance in the first run only if sdb5 is in the
        tree and inactive (it is), never a stop or restart (ADR-0004 D7)
    """
    pytest.skip("skeleton: implement in Phase 4 (installer)")


# AC-065: "Given uninstall run as root, then active steamos-mounter mounts are
#   unmounted and their mappings closed first. Every file the installer added
#   under /opt and /etc is removed ... The registry and keys are kept or deleted,
#   as the owner chooses. The next boot starts no steamos-mounter unit."
# ADR-0004 D8.6 (kept registry restored by the next install)
# ROI: 29 (BV:7 x Freq:3 + Legal:0 + Defect:8)
# Behavior: unwire (rule, udevadm reload, links, daemon-reload) -> stop key
#   units, then instances -> remove units and drop-in -> move registry to
#   kept-config.toml -> remove /run, /etc/steamos-mounter, /opt last -> a later
#   install moves the kept registry back
# @category: core-functionality
# @dependency: installer, manifest, wiring, systemd, config, atomicfile
# @complexity: high
# @real-dependency: tmp_path tree
def test_uninstall_default_unwires_first_keeps_registry_then_restores(
    tmp_path: Path,
    staged_release: Path,
) -> None:
    """Uninstall order, kept registry, and restore on the next install.

    Given
      - an installed tree (first install of the test above) with REGISTRY and
        MEDIABOX_KEY present, plus a record for MEDIABOX with busy == []
      - FakeRunner script: systemctl list-units ... steamos-mounter-key@* ->
        one key unit name; systemctl stop <units> -> 0 (blocking, 120 s);
        systemctl daemon-reload -> 0; udevadm control --reload -> 0
    When
      - report = installer.uninstall(ctx, purge=False)
      - then installer.install(ctx, release=tmp_path/RELEASE_DIR) again
    Then (pass criteria)
      - report.exit_code == ExitCode.OK; the FakeRunner log order is: udevadm
        control --reload (after the rule file is gone), systemctl daemon-reload
        (after the links are gone), systemctl stop of the key unit, systemctl
        stop of the registered and auto instances, systemctl daemon-reload
        (after the unit files are gone)
      - after uninstall: no ETC_FILES path, no MEDIABOX_LINK, no
        tmp_path/etc/steamos-mounter (removed when empty), no
        tmp_path/run/steamos-mounter, no tmp_path/OPT (removed last);
        tmp_path/KEPT_REGISTRY holds the former registry bytes and
        tmp_path/MEDIABOX_KEY still exists (keys stay); one report line names
        the kept path
      - after the re-install: tmp_path/REGISTRY is back with the same bytes,
        tmp_path/KEPT_REGISTRY is gone, MEDIABOX_LINK exists again, and the
        report has a step line for the restore
    """
    pytest.skip("skeleton: implement in Phase 4 (installer)")


# AC-065 "--purge" branch and the busy exit code (Commands table: uninstall exits
#   6 "done, but a mount needed a lazy unmount or a mapping a deferred close").
# ROI: 19 (BV:6 x Freq:2 + Legal:0 + Defect:7)
# Behavior: --purge deletes registry, keys and /var/lib/steamos-mounter; a busy
#   record turns into "still busy" lines and exit 6
# @category: edge-case
# @dependency: installer, state
# @complexity: medium
# @real-dependency: tmp_path tree
@pytest.mark.parametrize("variant", ["purge", "busy"])
def test_uninstall_purge_removes_secrets_and_busy_exits_6(
    variant: str,
    tmp_path: Path,
    staged_release: Path,
) -> None:
    """--purge leaves nothing; busy items are reported with exit 6.

    Given
      - an installed tree with REGISTRY and MEDIABOX_KEY; "busy": the
        MEDIABOX record's busy list holds "/run/media/deck/MEDIABOX" (a lazy
        unmount was needed when its instance stopped)
      - FakeRunner as in the test above
    When
      - "purge": report = installer.uninstall(ctx, purge=True)
      - "busy": report = installer.uninstall(ctx, purge=False)
    Then (pass criteria)
      - "purge": tmp_path/REGISTRY, tmp_path/KEYS_DIR and
        tmp_path/var/lib/steamos-mounter are gone; no KEPT_REGISTRY; exit OK;
        nothing of ours remains under tmp_path/etc, /opt or /run (SM-14)
      - "busy": exit_code == ExitCode.BUSY (6); one report line reads
        "still busy: finishes when the last open file is closed" naming the
        target; everything else is removed as in the default run
      - in both variants no step line has status "failed"
    """
    pytest.skip("skeleton: implement in Phase 4 (installer)")
