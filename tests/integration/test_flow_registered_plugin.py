"""Registered plug-in flow (MEDIABOX, dirty NTFS) - integration skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "Registered Plug-in
(MEDIABOX, dirty NTFS)", "NTFS Chain, Mount Options and Read-back",
"Notifications", "Runtime State Records"). Generated 2026-10-08 by the
acceptance-test-generator. Budget used: 2/3 integration for the feature
"registered plug-in" (FR-02, FR-04, FR-09). E2E for this feature lives in
tests/e2e/test_on_device_journeys.py.

Test boundary (Design Doc "Mock Boundary Decisions"): every external command
goes through FakeRunner; files, locks and records are real under
HostPaths(root=tmp_path) with trusted_uid = the test uid; /dev/kmsg is a
FakeKernelLog fed from fixtures/deck/journal-kernel-ntfs3.txt; the clock is a
FakeClock. Internal logic (routing, naming, config, state, chain planning) is
never mocked.

Fixtures expected from tests/conftest.py (helpers per the Design Doc layout:
fake_runner.py, fake_platform.py, host_tree.py, clock.py, builders.py):
fake_runner, fake_platform, host_tree, fake_kmsg, fake_clock, ctx. The test
functions below take only tmp_path until those helpers exist; add the fixture
parameters when implementing (Phase 3).

Skipped as a whole until steamos_mounter.reconcile exists (pytest.importorskip).
"""

from pathlib import Path

import pytest

# Modules crossed by this flow (gated so Phase 1 and 2 test runs stay green).
reconcile = pytest.importorskip("steamos_mounter.reconcile")
state = pytest.importorskip("steamos_mounter.state")

REPO = Path(__file__).resolve().parents[2]
DECK = REPO / "tests" / "fixtures" / "deck"

MEDIABOX_UUID = "01D95F1575592A30"
MEDIABOX_PATH = "/run/media/deck/MEDIABOX"
MEDIABOX_DEVICE_PATH = f"/dev/disk/by-uuid/{MEDIABOX_UUID}"
MEDIABOX_RECORD = "run/steamos-mounter/records/registered/01d95f1575592a30.json"
# Illustrative; the real syspath of sdb5 comes from fixtures/deck/sysfs-facts.txt.
SDB5_SYSPATH = (
    "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host0/"
    "target0:0:0/0:0:0:0/block/sdb/sdb5"
)
NTFS_RW_OPTIONS = "nosuid,nodev,uid=1000,gid=1000,umask=0022,windows_names"
KMSG_DIRTY_LINE = 'ntfs3(sdb5): volume is dirty and "force" flag is not set!'

# Registry (schema version 1) for the flows in this module. The emitter's header
# comment is omitted on purpose: config.parse ignores comments, and the real
# header line is longer than 88 columns.
REGISTRY_TEXT = """\
schema_version = 1

[[volume]]
name = "MEDIABOX"
uuid = "01D95F1575592A30"
path = "/run/media/deck/MEDIABOX"
fstype = "ntfs"
nosuid = true
nodev = true

[[volume]]
name = "PERSONAL"
uuid = "658207d5-5177-4a52-a297-31643c64724d"
path = "/run/media/deck/PERSONAL"
fstype = "BitLocker"
drivers = ["ntfs3", "ntfs-3g", "ntfs3:ro"]
nosuid = true
nodev = true
"""


@pytest.fixture
def registry_text() -> str:
    """Registry with MEDIABOX (ntfs) and PERSONAL (BitLocker), schema v1."""
    return REGISTRY_TEXT


@pytest.fixture
def expected_chain_argv() -> list[tuple[str, ...]]:
    """Exact argv of the three tool calls the dirty chain must make, in order.

    Targets are host-absolute (the FakeRunner never executes them); only the
    leaf directory is created under tmp_path by mounter.prepare_target.
    """
    return [
        ("/usr/bin/ntfs-3g.probe", "--readwrite", "/dev/sdb5"),
        (
            "/usr/bin/mount",
            "-i",
            "-t",
            "ntfs3",
            "-o",
            NTFS_RW_OPTIONS,
            "/dev/sdb5",
            MEDIABOX_PATH,
        ),
        ("/usr/bin/ntfs-3g", "-o", NTFS_RW_OPTIONS, "/dev/sdb5", MEDIABOX_PATH),
    ]


# AC-006: "Given MEDIABOX is registered, when it is plugged in during Desktop Mode
#   or Game Mode, then it is mounted at its fixed path within the latency target,
#   and no prompt of any kind appears."
# AC-016: "Given a dirty NTFS volume that is not in an unsafe state, then it ends
#   up mounted read-write by ntfs-3g as root, after ntfs3 refused it or the guard
#   skipped it. list shows the ntfs-3g driver and the dirty state. journald and a
#   notification warn that the volume is dirty and recommend chkdsk /f."
# AC-041, AC-046, AC-063 (journal entry, notification text, state from findmnt)
# ROI: 109 (BV:10 x Freq:10 + Legal:0 + Defect:9)
# Behavior: by-uuid device appears -> registered instance reconciles (START) ->
#   probe 15, ntfs3 refused (kmsg dirty line), ntfs-3g mounted, findmnt read-back
#   fuseblk rw -> MountedRWDirty recorded, NOTICE+WARNING journaled, notified
# @category: core-functionality
# @dependency: reconcile, routing, mounter, ntfs, kmsg, mounts, blockdev, config,
#   state, locks, session, notify, journal
# @complexity: high
# @real-dependency: tmp_path files (registry, by-uuid link, record), flock (holo
#   lock /var/run/jupiter-automount-sdb5.lock and the volume lock), journal socket
def test_registered_dirty_mediabox_mounts_rw_via_ntfs3g(tmp_path: Path) -> None:
    """Design Doc "Registered Plug-in (MEDIABOX, dirty NTFS)" end to end.

    Given
      - HostPaths(root=tmp_path) with /etc/steamos-mounter/config.toml =
        REGISTRY_TEXT (dir and file owned by the test uid, mode 0755/0644),
        /dev/disk/by-uuid/01D95F1575592A30 -> ../../sdb5, sysfs from
        fixtures/deck/sysfs-facts.txt, no /run/media/deck yet, no records.
      - FakeRunner script:
        lsblk --json --bytes --tree -o <LSBLK_COLUMNS>
            -> fixtures/deck/lsblk-columns-tree.json (rc 0)
        findmnt --json -o <FINDMNT_COLUMNS> --list --real
            -> fixtures/deck/findmnt-real-list.json (sdb5 absent; use a
               synthetic copy without sdb5 if the capture shows it mounted)
        ntfs-3g.probe --readwrite /dev/sdb5 -> rc 15 (dirty)
        mount -i -t ntfs3 ... /dev/sdb5 /run/media/deck/MEDIABOX -> rc 32,
            and FakeKernelLog yields KMSG_DIRTY_LINE after the mark
        findmnt ... --mountpoint /run/media/deck/MEDIABOX
            -> 1st: fixtures/deck/findmnt-sdb5-not-mounted.json (rc 1, 0 bytes)
            -> 2nd: fixtures/synthetic/findmnt-mediabox-fuseblk-rw.json (rc 0)
        ntfs-3g -o ... /dev/sdb5 /run/media/deck/MEDIABOX -> rc 0
        loginctl show-user deck -p Display -> fixtures/deck/loginctl-user-deck.txt
        loginctl show-seat seat0 -p ActiveSession -> "ActiveSession=5"
        loginctl show-session 5 -p ... ->
            fixtures/deck/loginctl-session-5-properties.txt (Desktop verdict)
        systemd-run --user --wait --quiet --collect /usr/bin/notify-send ...
            -> rc 0 (as uid 1000, gid 1000)
    When
      - reconcile.run(ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE_PATH,
        Trigger.START)
      - then reconcile.run(ctx, InstanceKind.AUTO, SDB5_SYSPATH, Trigger.START)
        for the auto instance systemd starts in parallel (SYSTEMD_WANTS)
    Then (pass criteria)
      - outcome.state == VolumeState.MOUNTED_RW_DIRTY, outcome.reason == "dirty"
      - the three chain calls equal expected_chain_argv, in that order; no other
        mount, ntfs-3g or probe call; no "noexec", "force" or "remove_hiberfile"
        in any argv (AC-079, ADR-0003 Decision 4)
      - record tmp_path/MEDIABOX_RECORD: format 1, state "MountedRWDirty",
        mount.status "mounted", mount.driver "ntfs-3g", mount.mode "rw",
        mount.target MEDIABOX_PATH, mount.created_dir true, attempt.probe
        {"code": 15, "class": "dirty"}, attempt.steps = [ntfs3 rw refused with
        detail KMSG_DIRTY_LINE, ntfs-3g rw mounted], attempt.skipped == []
      - the record file was written with mount.status "pending" before the
        first chain call (write-ahead, DD-10; observe through the FakeRunner's
        call hook or a record snapshot taken when the probe runs)
      - tmp_path/run/media/deck/MEDIABOX exists (leaf only, DD-26);
        tmp_path/var/run/jupiter-automount-sdb5.lock exists (holo lock taken
        around the mount, ADR-0002 D5)
      - caplog has a NOTICE "mounted" entry and a WARNING "dirty" entry with
        SM_VOLUME=MEDIABOX, SM_EVENT=reconcile (AC-041)
      - exactly one notify-send transport call: argv contains "-a",
        "steamos-mounter", "-u", "normal", summary "MEDIABOX is dirty", body
        "Mounted read-write with ntfs-3g at /run/media/deck/MEDIABOX. Run
        chkdsk /f on it in Windows." (AC-046); user == 1000
      - the auto instance pass returns Route action YIELD, writes no record under
        records/auto/, and adds no mount, probe or ntfs-3g call to the log
      - state.compute_views(...) over the same inputs renders MEDIABOX as
        "mounted read-write via ntfs-3g (dirty)" with next step
        "Run chkdsk /f on it in Windows." (AC-040, AC-063)
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")


# AC-035: "Given repeated or concurrent events for the same partition, then
#   exactly one mount results."
# Design Doc "Required Specific Tests" 2: "reconcile start and reconcile reload
#   back to back on the same volume -> one mount, second pass is a no-op".
# ROI: 64 (BV:8 x Freq:7 + Legal:0 + Defect:8)
# Behavior: START mounts -> RELOAD finds the mount at its own target through the
#   held check -> no second mount, record unchanged apart from trigger/updated_at
# @category: integration
# @dependency: reconcile, mounts, state, locks
# @complexity: medium
# @real-dependency: tmp_path records, flock (volume lock taken twice in sequence)
def test_registered_start_then_reload_mounts_exactly_once(tmp_path: Path) -> None:
    """Back-to-back START and RELOAD on MEDIABOX produce one mount.

    Given
      - the same tree, registry and FakeRunner script as the test above, except
        that the --list --real findmnt answer changes after the first pass to a
        synthetic list that includes /dev/sdb5 at /run/media/deck/MEDIABOX
        (fixtures/synthetic/findmnt-list-with-mediabox.json)
    When
      - reconcile.run(... REGISTERED, MEDIABOX_DEVICE_PATH, Trigger.START)
      - reconcile.run(... REGISTERED, MEDIABOX_DEVICE_PATH, Trigger.RELOAD)
    Then (pass criteria)
      - the FakeRunner log holds exactly one probe, one ntfs3 attempt and one
        ntfs-3g call in total (all from the first pass)
      - the second outcome is "already mounted": state stays MountedRWDirty,
        no new attempt entry, record.trigger == "reload", record.cli_request is
        None (cleared, D014), record.unmounted_by_user is None
      - the lock file locks/volume-01d95f1575592a30.lock exists and is not held
        after both passes (a third flock(LOCK_EX | LOCK_NB) succeeds)
    Note: the threaded variant with real flock contention is a unit test
    (tests/unit/test_reconcile.py::test_concurrent_reconcile_one_mount, AC-035).
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")
