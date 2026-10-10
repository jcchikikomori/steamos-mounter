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

The "--release equals the running entry point's release root" rule is met
through ``Context.release_root`` (work plan decision item 2): the tests build
the context the staged release's entry point would build, with
``installer_env.release_ctx``.
"""

import json
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from tests.helpers.builders import record_dict
from tests.helpers.cli_env import (
    MEDIABOX_RECORD,
    MEDIABOX_REGISTRY,
    MEDIABOX_UNIT,
    MEDIABOX_UUID,
    script_tree,
    script_unit,
    verb_argv,
)
from tests.helpers.dropin import DROPIN_FILE, dropin_patterns, glob_matches
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import (
    SETFACL,
    SYSTEMCTL,
    known_os_set,
    write_key_file,
    write_record,
    write_registry,
)
from tests.helpers.installer_env import (
    DAEMON_RELOAD,
    ETC_FILES,
    INSTANCES,
    KEPT_REGISTRY,
    KEY_UNITS,
    KEYS_DIR,
    OPT,
    REGISTRY,
    RELEASE_NAME,
    RELEASES,
    UDEVADM_RELOAD,
    paths_under,
    pinned_umask,
    release_ctx,
    snapshot,
    stage_release,
    system_tree,
    units_answer,
)

from steamos_mounter import installer
from steamos_mounter.errors import ExitCode
from steamos_mounter.installer_report import StepLine

RELEASE_DIR = f"{RELEASES}/{RELEASE_NAME}"
MEDIABOX_KEY = f"{KEYS_DIR}/{MEDIABOX_UUID}.key"
MEDIABOX_LINK = (
    "etc/systemd/system/dev-disk-by\\x2duuid-01D95F1575592A30.device.wants/"
    "steamos-mounter@dev-disk-by\\x2duuid-01D95F1575592A30.service"
)
TEMPLATE = "/etc/systemd/system/steamos-mounter@.service"
RUN_ROWS = {
    "run/steamos-mounter": 0o755,
    "run/steamos-mounter/records": 0o755,
    "run/steamos-mounter/records/registered": 0o755,
    "run/steamos-mounter/records/auto": 0o755,
    "run/steamos-mounter/locks": 0o700,
}
# The Deck capture: PERSONAL (sdb1, BitLocker, unlocked by Dolphin as dm-0)
# is unregistered, so its partition and its mapping get auto instances.
SDB1_AUTO = "steamos-mounter-auto@sys-devices-host\\x2dtree-block-sdb-sdb1.service"
DM0_AUTO = "steamos-mounter-auto@sys-devices-virtual-block-dm\\x2d0.service"
KEY_UNIT = MEDIABOX_UNIT.replace("steamos-mounter@", "steamos-mounter-key@")
STILL_BUSY = "still busy: finishes when the last open file is closed"


@pytest.fixture
def staged_release(tmp_path: Path) -> Iterator[Path]:
    """Stage the repository as a root-owned-looking release under tmp_path.

    Copies REPO/bin, REPO/data, REPO/README.md and REPO/src/steamos_mounter (as
    lib/steamos_mounter) into tmp_path/RELEASE_DIR with the install.sh modes;
    __pycache__ directories are dropped. Returns the release path. The test
    process runs with umask 022 (what install.sh sets), whatever the host's.
    """
    with pinned_umask():
        system_tree(tmp_path)
        yield stage_release(tmp_path)


@pytest.fixture
def deck(ctx, tmp_path: Path, host_tree, fake_runner, staged_release: Path):
    """The Deck after a reboot: MEDIABOX registered and plugged, its key stored.

    No ``/run/steamos-mounter`` and no ``/run/media`` yet. Every instance is
    inactive until something starts it.
    """
    write_registry(tmp_path, MEDIABOX_REGISTRY)
    write_key_file(tmp_path, MEDIABOX_UUID, b"TEST-KEY")
    known_os_set(tmp_path)
    host_tree.add_sysfs_facts()
    host_tree.link_by_uuid(MEDIABOX_UUID, "sdb5")
    fake_runner.on(DAEMON_RELOAD, Answer(), repeat=True)
    fake_runner.on(UDEVADM_RELOAD, Answer(), repeat=True)
    fake_runner.on(SETFACL, Answer(), repeat=True)
    script_tree(fake_runner)
    for unit in (MEDIABOX_UNIT, DM0_AUTO, SDB1_AUTO):
        script_unit(fake_runner, unit, "inactive", "active")
        fake_runner.on(verb_argv("start", unit, block=False), Answer())
    return release_ctx(ctx, staged_release)


def install(ctx, tmp_path: Path):
    return installer.install(ctx, release=tmp_path / RELEASE_DIR)


def starts(runner, since: int = 0) -> list[tuple[str, ...]]:
    return [argv for argv in runner.argvs[since:] if argv[1:2] == ("start",)]


def script_uninstall(runner, *, on_instances_stop: Callable | None = None) -> None:
    runner.on(KEY_UNITS, units_answer(KEY_UNIT))
    runner.on((SYSTEMCTL, "stop", "--", KEY_UNIT), Answer())
    runner.on(INSTANCES, units_answer(MEDIABOX_UNIT, SDB1_AUTO))
    runner.on(
        (SYSTEMCTL, "stop", "--", MEDIABOX_UNIT, SDB1_AUTO),
        Answer(),
        hook=on_instances_stop,
    )


def teardown_writes_record(tmp_path: Path, busy: list[str]) -> Callable:
    """What MEDIABOX's ExecStop does while ``systemctl stop`` blocks: its record."""

    def stopped(_command) -> None:
        record = record_dict(key=MEDIABOX_UUID.lower(), name="MEDIABOX", busy=busy)
        write_record(tmp_path, MEDIABOX_RECORD, json.dumps(record).encode())

    return stopped


def files_holding(root: Path, data: bytes) -> list[Path]:
    return [
        path
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink() and data in path.read_bytes()
    ]


def kept_by_dropin(path: str, patterns: list[str]) -> bool:
    return any(glob_matches(pattern, f"/{path}") for pattern in patterns)


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
    deck,
    fake_runner,
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
      - snapshot = {relative path: (type, mode, owner, inode, and for files
        and links mtime plus sha256 or link target)} over tmp_path, excluding
        __pycache__
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
      - every path the first install adds under tmp_path/etc is kept by a
        data/steamos-mounter.conf pattern (a new directory only as the parent
        of such a path); no file under tmp_path/etc holds the key bytes
      - the FakeRunner log holds, per run, one daemon-reload after the links
        and one udevadm control --reload; in the first run only, after both
        reloads, three systemctl start --no-block: MEDIABOX's registered
        instance (sdb5 is in the tree and inactive), then the auto instances of
        the unregistered PERSONAL mapping dm-0 and its container sdb1; never a
        stop or restart (ADR-0004 D7)
    """
    secrets = {
        path: ((tmp_path / path).read_bytes(), os.stat(tmp_path / path))
        for path in (REGISTRY, MEDIABOX_KEY)
    }

    etc_before = paths_under(tmp_path / "etc")

    first = install(deck, tmp_path)
    first_calls = len(fake_runner.argvs)
    etc_added = paths_under(tmp_path / "etc") - etc_before
    tree = snapshot(tmp_path)
    second = install(deck, tmp_path)

    assert first.exit_code == ExitCode.OK, first.lines
    assert {line.status for line in first.lines} <= {"ok", "skipped"}
    assert os.readlink(tmp_path / OPT / "current") == f"releases/{RELEASE_NAME}"
    assert os.readlink(tmp_path / OPT / "bin") == "current/bin"
    for path in ETC_FILES:
        installed = tmp_path / path
        assert stat.S_IMODE(installed.stat().st_mode) == 0o644
        source = tmp_path / RELEASE_DIR / "data" / Path(path).name
        assert installed.read_bytes() == source.read_bytes()
    wants = (tmp_path / MEDIABOX_LINK).parent
    assert os.readlink(tmp_path / MEDIABOX_LINK) == TEMPLATE
    assert os.listdir(wants) == [Path(MEDIABOX_LINK).name]
    patterns = dropin_patterns(DROPIN_FILE.read_text(encoding="utf-8"))
    kept = {path for path in etc_added if kept_by_dropin(path, patterns)}
    parents = {str(Path(path).parent) for path in kept}
    assert kept == {*ETC_FILES, MEDIABOX_LINK}
    assert etc_added - kept == {str(wants.relative_to(tmp_path))}
    assert etc_added - kept <= parents
    assert files_holding(tmp_path / "etc", b"TEST-KEY") == []
    for path, mode in RUN_ROWS.items():
        assert stat.S_IMODE(os.lstat(tmp_path / path).st_mode) == mode
    assert second.exit_code == ExitCode.OK
    assert snapshot(tmp_path) == tree
    writes = [line for line in second.lines if line.step.startswith("write ")]
    assert len(writes) == len(ETC_FILES)
    assert {line.status for line in writes} == {"skipped"}
    for path, (data, before) in secrets.items():
        after = os.stat(tmp_path / path)
        assert (tmp_path / path).read_bytes() == data
        assert after.st_mode == before.st_mode
        assert after.st_mtime_ns == before.st_mtime_ns
    for path in (tmp_path / OPT).rglob("*"):
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):  # a symlink's own mode is always 0777
            assert path.name in ("current", "bin")
            assert path.parent == tmp_path / OPT
        else:
            assert not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH), path
    for run in (fake_runner.argvs[:first_calls], fake_runner.argvs[first_calls:]):
        assert run.count(DAEMON_RELOAD) == 1
        assert run.count(UDEVADM_RELOAD) == 1
    first_run = fake_runner.argvs[:first_calls]
    assert starts(fake_runner) == [
        verb_argv("start", MEDIABOX_UNIT, block=False),
        verb_argv("start", DM0_AUTO, block=False),
        verb_argv("start", SDB1_AUTO, block=False),
    ]
    reloads = max(first_run.index(DAEMON_RELOAD), first_run.index(UDEVADM_RELOAD))
    assert all(first_run.index(argv) > reloads for argv in starts(fake_runner))
    assert starts(fake_runner, first_calls) == []
    verbs = {argv[1] for argv in fake_runner.argvs if argv[0] == SYSTEMCTL}
    assert verbs.isdisjoint({"stop", "restart", "reload"})


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
    deck,
    fake_runner,
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
    assert install(deck, tmp_path).exit_code == ExitCode.OK
    registry = (tmp_path / REGISTRY).read_bytes()
    script_uninstall(
        fake_runner, on_instances_stop=teardown_writes_record(tmp_path, [])
    )
    since = len(fake_runner.argvs)

    report = installer.uninstall(deck, purge=False)

    assert report.exit_code == ExitCode.OK, report.lines
    assert fake_runner.argvs[since:] == [
        UDEVADM_RELOAD,
        DAEMON_RELOAD,
        KEY_UNITS,
        (SYSTEMCTL, "stop", "--", KEY_UNIT),
        INSTANCES,
        (SYSTEMCTL, "stop", "--", MEDIABOX_UNIT, SDB1_AUTO),
        DAEMON_RELOAD,
    ]
    assert not any(os.path.lexists(tmp_path / path) for path in ETC_FILES)
    assert not os.path.lexists(tmp_path / MEDIABOX_LINK)
    for gone in ("etc/steamos-mounter", "run/steamos-mounter", OPT):
        assert not os.path.lexists(tmp_path / gone)
    assert (tmp_path / KEPT_REGISTRY).read_bytes() == registry
    assert (tmp_path / MEDIABOX_KEY).exists()
    assert (
        StepLine(
            "registry",
            "ok",
            "kept at /var/lib/steamos-mounter/kept-config.toml; keys kept",
        )
        in report.lines
    )
    assert files_holding(tmp_path / "etc", b"TEST-KEY") == []

    stage_release(tmp_path)
    again = install(deck, tmp_path)

    assert again.exit_code == ExitCode.OK, again.lines
    assert (tmp_path / REGISTRY).read_bytes() == registry
    assert not (tmp_path / KEPT_REGISTRY).exists()
    assert os.readlink(tmp_path / MEDIABOX_LINK) == TEMPLATE
    restore = next(line for line in again.lines if line.step == "kept registry")
    assert restore.status == "ok"


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
    deck,
    fake_runner,
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
    etc_before = paths_under(tmp_path / "etc")
    assert install(deck, tmp_path).exit_code == ExitCode.OK
    busy = ["/run/media/deck/MEDIABOX"] if variant == "busy" else []
    script_uninstall(
        fake_runner, on_instances_stop=teardown_writes_record(tmp_path, busy)
    )

    report = installer.uninstall(deck, purge=variant == "purge")

    assert "failed" not in {line.status for line in report.lines}
    for gone in (*ETC_FILES, "etc/steamos-mounter", "run/steamos-mounter", OPT):
        assert not os.path.lexists(tmp_path / gone)
    if variant == "purge":
        assert report.exit_code == ExitCode.OK
        for gone in (REGISTRY, KEYS_DIR, "var/lib/steamos-mounter"):
            assert not os.path.lexists(tmp_path / gone)
        # The host's /etc as before the install, minus the registry --purge
        # deletes on purpose: no unit, rule, drop-in, wants link or wants dir.
        registry_paths = {str(Path(REGISTRY).parent), REGISTRY}
        assert paths_under(tmp_path / "etc") == etc_before - registry_paths
    else:
        assert report.exit_code == ExitCode.BUSY
        busy_lines = [line for line in report.lines if line.status == "busy"]
        assert len(busy_lines) == 1
        assert busy_lines[0].step == "MEDIABOX"
        assert busy_lines[0].detail == f"/run/media/deck/MEDIABOX {STILL_BUSY}"
        assert report.lines[-1] == busy_lines[0]
        assert (tmp_path / KEPT_REGISTRY).exists()
