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

import fcntl
import logging
import os
from pathlib import Path

import pytest
from tests.helpers.fake_kmsg import FakeKernelLog
from tests.helpers.fake_runner import Answer, FakeRunner
from tests.helpers.flows import (
    MOUNT,
    NTFS3G,
    PROBE,
    SETFACL,
    SYSTEMD_RUN,
    TABLE_ARGV,
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
from tests.helpers.host_tree import HostTree

from steamos_mounter import blockdev, config, mounts
from steamos_mounter.journal import NOTICE
from steamos_mounter.model import InstanceKind, Trigger, VolumeState
from steamos_mounter.routing import Action

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
# The record keeps the message without the "ntfs3(sdb5): " prefix, as the
# Design Doc's Record Schema example shows (mounter strips it).
RECORDED_DIRTY_DETAIL = KMSG_DIRTY_LINE.removeprefix("ntfs3(sdb5): ")
MEDIABOX_LOCK = "run/steamos-mounter/locks/volume-01d95f1575592a30.lock"
NOTIFY_SUMMARY = "MEDIABOX is dirty"
NOTIFY_BODY = (
    "Mounted read-write with ntfs-3g at /run/media/deck/MEDIABOX. Run chkdsk /f on"
    " it in Windows."
)
FORBIDDEN_OPTIONS = ("noexec", "force", "remove_hiberfile")
NOT_MOUNTED = Answer.from_fixture("findmnt-sdb5-not-mounted.json")
MEDIABOX_FUSE_RW = Answer.from_fixture("findmnt-mediabox-fuseblk-rw.json", returncode=0)
REAL_TABLE = Answer.from_fixture("findmnt-real-list.json")
TABLE_WITH_MEDIABOX = Answer.from_fixture(
    "findmnt-list-with-mediabox.json", returncode=0
)

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


def given_mediabox_plugged_in(
    ctx,
    tmp_path: Path,
    host_tree: HostTree,
    fake_runner: FakeRunner,
    fake_kmsg: FakeKernelLog,
    registry_text: str,
    *,
    probe_code: int = 15,
    probe_hook=None,
) -> None:
    """The Given of this module: tree, registry, sysfs and the dirty chain script."""
    runtime_dirs(ctx)
    write_registry(tmp_path, registry_text)
    host_tree.add_sysfs_facts()
    host_tree.link_by_uuid(MEDIABOX_UUID, "sdb5")
    make_var_run(tmp_path)  # holo's /var/run; no /run/media/deck yet
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, REAL_TABLE, TABLE_WITH_MEDIABOX)
    fake_runner.on(SETFACL, Answer())
    fake_runner.on(PROBE, Answer(returncode=probe_code), hook=probe_hook)
    fake_runner.on(MOUNT, Answer(returncode=32))
    fake_runner.on(readback_argv(MEDIABOX_PATH), NOT_MOUNTED, MEDIABOX_FUSE_RW)
    fake_runner.on(NTFS3G, Answer())
    script_desktop_session(fake_runner)
    script_notify(fake_runner)
    fake_kmsg.queue(KMSG_DIRTY_LINE)


def chain_argvs(fake_runner: FakeRunner) -> list[tuple[str, ...]]:
    return [argv for argv in fake_runner.argvs if argv[0] in {PROBE, MOUNT, NTFS3G}]


def options_in(argvs) -> set[str]:
    return {option for argv in argvs for item in argv for option in item.split(",")}


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
@pytest.mark.parametrize(
    ("probe_code", "probe_class"),
    [(15, "dirty"), (0, "safe")],
    # Probe 0 is what the owner's real MEDIABOX gives (dirty flag only); the
    # kernel's refusal line is the dirty evidence then.
    ids=["probe-15", "probe-0-owner-mediabox"],
)
def test_registered_dirty_mediabox_mounts_rw_via_ntfs3g(
    tmp_path: Path,
    ctx,
    host_tree,
    fake_runner,
    fake_kmsg,
    caplog,
    registry_text,
    expected_chain_argv,
    probe_code,
    probe_class,
) -> None:
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
        detail = the kmsg line without the ntfs3(<kname>): prefix (Record
        Schema example), ntfs-3g rw mounted], attempt.skipped == []
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
    caplog.set_level(logging.DEBUG)
    ahead = []
    given_mediabox_plugged_in(
        ctx,
        tmp_path,
        host_tree,
        fake_runner,
        fake_kmsg,
        registry_text,
        probe_code=probe_code,
        probe_hook=lambda _c: ahead.append(read_record(tmp_path, MEDIABOX_RECORD)),
    )

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE_PATH, Trigger.START
    )
    calls_after_registered = len(fake_runner.argvs)
    auto = reconcile.run(ctx, InstanceKind.AUTO, SDB5_SYSPATH, Trigger.START)

    assert (outcome.state, outcome.reason) == (VolumeState.MOUNTED_RW_DIRTY, "dirty")
    assert chain_argvs(fake_runner) == expected_chain_argv
    assert options_in(fake_runner.argvs).isdisjoint(FORBIDDEN_OPTIONS)
    record = read_record(tmp_path, MEDIABOX_RECORD)
    assert record["format"] == 1
    assert record["state"] == "MountedRWDirty"
    assert record["mount"] == {
        "status": "mounted",
        "target": MEDIABOX_PATH,
        "device": "/dev/sdb5",
        "devnum": "8:21",
        "driver": "ntfs-3g",
        "mode": "rw",
        "created_dir": True,
    }
    assert record["attempt"] == {
        "probe": {"code": probe_code, "class": probe_class},
        "steps": [
            {
                "driver": "ntfs3",
                "mode": "rw",
                "result": "refused",
                "detail": RECORDED_DIRTY_DETAIL,
            },
            {"driver": "ntfs-3g", "mode": "rw", "result": "mounted", "detail": ""},
        ],
        "skipped": [],
    }
    [written_ahead] = ahead  # snapshot taken when the probe ran (DD-10)
    assert written_ahead["mount"]["status"] == "pending"
    assert written_ahead["mount"]["target"] == MEDIABOX_PATH
    assert (tmp_path / MEDIABOX_PATH.lstrip("/")).is_dir()
    assert (tmp_path / "var/run/jupiter-automount-sdb5.lock").exists()
    reconcile_logs = [
        r for r in caplog.records if sm_fields(r).get("SM_EVENT") == "reconcile"
    ]
    assert any(
        r.levelno == NOTICE
        and "mounted" in r.getMessage()
        and sm_fields(r).get("SM_VOLUME") == "MEDIABOX"
        for r in reconcile_logs
    )
    assert any(
        r.levelno == logging.WARNING
        and "dirty" in r.getMessage()
        and sm_fields(r).get("SM_VOLUME") == "MEDIABOX"
        for r in reconcile_logs
    )
    [notification] = [call for call in fake_runner.calls if call.argv[0] == SYSTEMD_RUN]
    assert notification.user == 1000
    argv = notification.argv
    assert argv[argv.index("-a") + 1] == "steamos-mounter"
    assert argv[argv.index("-u") + 1] == "normal"
    assert argv[-2:] == (NOTIFY_SUMMARY, NOTIFY_BODY)
    # The auto instance systemd starts for the same partition yields.
    assert auto.route.action is Action.YIELD
    assert os.listdir(tmp_path / "run/steamos-mounter/records/auto") == []
    assert all(
        argv[0] not in {PROBE, MOUNT, NTFS3G}
        for argv in fake_runner.argvs[calls_after_registered:]
    )
    views = state.compute_views(
        ctx, config.load(ctx), blockdev.read_tree(ctx), mounts.table(ctx)
    )
    [mediabox] = [view for view in views if view.name == "MEDIABOX"]
    assert state.words(mediabox.state, mediabox.reason) == (
        "mounted read-write via ntfs-3g (dirty)"
    )
    assert mediabox.next_step == "Run chkdsk /f on it in Windows."


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
def test_registered_start_then_reload_mounts_exactly_once(
    tmp_path: Path, ctx, host_tree, fake_runner, fake_kmsg, registry_text
) -> None:
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
      - the reload is a no-op: exactly one notification (systemd-run) in the
        whole log, and the record equals the post-START record apart from
        trigger and updated_at
      - the lock file locks/volume-01d95f1575592a30.lock exists and is not held
        after both passes (a third flock(LOCK_EX | LOCK_NB) succeeds)
    Note: the threaded variant with real flock contention is a unit test
    (tests/unit/test_reconcile.py::test_concurrent_reconcile_one_mount, AC-035).
    """
    given_mediabox_plugged_in(
        ctx, tmp_path, host_tree, fake_runner, fake_kmsg, registry_text
    )

    first = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE_PATH, Trigger.START
    )
    after_start = read_record(tmp_path, MEDIABOX_RECORD)
    second = reconcile.run(
        ctx, InstanceKind.REGISTERED, MEDIABOX_DEVICE_PATH, Trigger.RELOAD
    )

    assert first.state is VolumeState.MOUNTED_RW_DIRTY
    assert [argv[0] for argv in chain_argvs(fake_runner)] == [PROBE, MOUNT, NTFS3G]
    assert second.state is VolumeState.MOUNTED_RW_DIRTY
    record = read_record(tmp_path, MEDIABOX_RECORD)
    assert record["state"] == "MountedRWDirty"
    assert record["attempt"] == after_start["attempt"]  # no new attempt entry
    assert record["trigger"] == "reload"
    volatile = {"trigger", "updated_at"}
    assert {k: v for k, v in record.items() if k not in volatile} == {
        k: v for k, v in after_start.items() if k not in volatile
    }
    notifications = [argv for argv in fake_runner.argvs if argv[0] == SYSTEMD_RUN]
    assert len(notifications) == 1  # START notified; RELOAD did not
    assert (record["cli_request"], record["unmounted_by_user"]) == (None, None)
    lock = os.open(tmp_path / MEDIABOX_LOCK, os.O_RDWR)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # not held after both
    finally:
        os.close(lock)
