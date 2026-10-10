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

import json
import logging
import os
from pathlib import Path

import pytest
from tests.helpers.builders import MEDIABOX, PERSONAL, registry_text
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture
from tests.helpers.flows import (
    CRYPTSETUP,
    LOGINCTL,
    MOUNT,
    NTFS3G,
    PROBE,
    SYSTEMCTL,
    SYSTEMD_RUN,
    TABLE_ARGV,
    make_mount_base,
    make_var_run,
    read_record,
    readback_argv,
    runtime_dirs,
    script_key_unit,
    script_lsblk,
    sm_fields,
    write_registry,
)

from steamos_mounter import blockdev, config, mounts
from steamos_mounter.journal import NOTICE
from steamos_mounter.model import InstanceKind, Trigger, VolumeState
from steamos_mounter.routing import Action

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
KEY_UNIT = f"steamos-mounter-key@{PERSONAL_INSTANCE}.service"
DM0_SYSPATH = "/sys/devices/virtual/block/dm-0"
DM0_RECORD = "run/steamos-mounter/records/auto/dm-0-252_0.json"
CLI_ROOT = "sudo /opt/steamos-mounter/bin/steamos-mounter"
ABSENT_NEXT_STEP = CLI_ROOT + " mount --device /dev/sdb1"
ELSEWHERE_NEXT_STEP = (
    "Unmount it there, then run " + CLI_ROOT + " mount --volume PERSONAL to use"
    " the fixed path."
)
UDISKS_PATH = "/run/media/deck/PERSONAL1"
DM0_AT_UDISKS_PATH = "findmnt-list-dm0-at-udisks-path.json"
UDISKS_NAME = "PAT4T4SHUAWEI_PERSONAL_4_3_2024"  # DM_NAME in udev-dm-0.txt
NTFS_RW_OPTIONS = "nosuid,nodev,uid=1000,gid=1000,umask=0022,windows_names"


def given_personal_unlocked_in_dolphin(ctx, tmp_path: Path, host_tree) -> None:
    """Registry with MEDIABOX and PERSONAL, the Deck's sysfs, no PERSONAL record."""
    runtime_dirs(ctx)
    write_registry(tmp_path, registry_text([MEDIABOX, PERSONAL]))
    host_tree.add_sysfs_facts()  # dm-0/slaves=sdb1, sdb1/holders=dm-0, dm/name
    host_tree.link_by_uuid(PERSONAL_UUID, "sdb1")
    make_mount_base(tmp_path)
    make_var_run(tmp_path)


def dm0_mounted_at(target: str) -> Answer:
    """The synthetic findmnt list with udisks' dm-0 row moved to ``target``."""
    document = json.loads(load_fixture(DM0_AT_UDISKS_PATH))
    document["filesystems"][-1]["target"] = target
    return Answer(stdout=json.dumps(document).encode(), returncode=0)


def outcome_notices(caplog, volume_state: str) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.levelno == NOTICE
        and sm_fields(r).get("SM_STATE") == volume_state
        and sm_fields(r).get("SM_EVENT") == "reconcile"
    ]


def files_under(root: Path) -> list[str]:
    return sorted(
        str(Path(directory, name).relative_to(root))
        for directory, _, names in os.walk(root)
        for name in names
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
    tmp_path: Path, ctx, host_tree, fake_runner, systemctl_show_active
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
        record mapping.opened_by "other" and mapping.name == the udisks name;
        the probe and mount calls are exactly [probe --readwrite /dev/dm-0,
        mount -i -t ntfs3 -o <NTFS_RW_OPTIONS> /dev/dm-0 PERSONAL_PATH]
      - no argv anywhere contains a path under /run/media/deck other than
        PERSONAL_PATH (AC-059); no cryptsetup call; no key unit start
      - a delegated RELOAD never starts the key unit even though no stored key
        exists (ADR-0005 D1.3): no "systemctl start" in the log at all; the
        registered pass only asks whether a key unit is running (ADR-0005
        D5.2), and none is
    """
    given_personal_unlocked_in_dolphin(ctx, tmp_path, host_tree)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on((SYSTEMCTL, "show"), Answer(stdout=systemctl_show_active.encode()))
    fake_runner.on((SYSTEMCTL, "reload", "--no-block"), Answer())
    script_key_unit(fake_runner)
    fake_runner.on(TABLE_ARGV, "findmnt-real-list.json")
    fake_runner.on(PROBE, Answer())
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(
        readback_argv(PERSONAL_PATH),
        Answer.from_fixture("findmnt-personal-ntfs3-rw.json", returncode=0),
    )

    first = reconcile.run(ctx, InstanceKind.AUTO, DM0_SYSPATH, Trigger.START)
    first_pass = list(fake_runner.argvs)
    second = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH, Trigger.RELOAD
    )

    assert first.route.action is Action.DELEGATE
    assert first.route.delegate_unit == REGISTERED_UNIT  # never an auto unit
    assert first.reason == "reloaded"
    assert not (tmp_path / DM0_RECORD).exists()
    assert all(argv[0] != MOUNT for argv in first_pass)
    assert second.route.action is Action.MOUNT_INNER_REGISTERED
    assert second.state is VolumeState.MOUNTED_RW
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert (record["mount"]["target"], record["mount"]["device"]) == (
        PERSONAL_PATH,
        "/dev/dm-0",
    )
    assert (record["mapping"]["opened_by"], record["mapping"]["name"]) == (
        "other",
        UDISKS_NAME,
    )
    assert [argv for argv in fake_runner.argvs if argv[0] in {PROBE, MOUNT}] == [
        (PROBE, "--readwrite", "/dev/dm-0"),
        (MOUNT, "-i", "-t", "ntfs3", "-o", NTFS_RW_OPTIONS, "/dev/dm-0", PERSONAL_PATH),
    ]
    under_base = {
        item
        for argv in fake_runner.argvs
        for item in argv
        if item.startswith("/run/media/deck/")
    }
    assert under_base == {PERSONAL_PATH}  # AC-059: only the fixed path
    assert all(argv[0] != CRYPTSETUP for argv in fake_runner.argvs)
    # The verb and the unit of each call; the unit is always the last item.
    assert [
        (argv[1], argv[-1]) for argv in fake_runner.argvs if argv[0] == SYSTEMCTL
    ] == [
        ("show", REGISTERED_UNIT),
        ("reload", REGISTERED_UNIT),
        ("show", KEY_UNIT),  # the key unit's state (ADR-0005 D5.2): inactive
    ]  # no "systemctl start": no key unit for a delegated reload (ADR-0005 D1.3)


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
    tmp_path: Path, ctx, host_tree, fake_runner, caplog, systemctl_show_inactive
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
      - outcome.route.action == Action.DELEGATE, outcome state NotMounted with
        reason "no_partition_instance"
      - request_reconcile result "absent"; the log holds the systemctl show and
        no systemctl start or reload (D006: never start what the owner or
        systemd stopped); caplog has one WARNING "no partition instance"
      - tmp_path/DM0_RECORD exists with kind "auto", key "dm-0-252_0", state
        "NotMounted", reason "no_partition_instance", next_step ==
        ABSENT_NEXT_STEP, mapping and mount describing nothing mounted
      - views contains one AUTO entry, named PERSONAL, for the dm-0 record with state
        VolumeState.NOT_MOUNTED, words "present, not mounted yet" and the next
        step above; compute_views wrote no file (directory listing unchanged)
    """
    caplog.set_level(logging.DEBUG)
    given_personal_unlocked_in_dolphin(ctx, tmp_path, host_tree)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on((SYSTEMCTL, "show"), Answer(stdout=systemctl_show_inactive.encode()))
    fake_runner.on(TABLE_ARGV, "findmnt-real-list.json")

    outcome = reconcile.run(ctx, InstanceKind.AUTO, DM0_SYSPATH, Trigger.START)
    files_before = files_under(tmp_path)
    views = state.compute_views(
        ctx, config.load(ctx), blockdev.read_tree(ctx), mounts.table(ctx)
    )

    assert outcome.route.action is Action.DELEGATE
    assert (outcome.state, outcome.reason) == (
        VolumeState.NOT_MOUNTED,
        "no_partition_instance",
    )
    assert [argv[1] for argv in fake_runner.argvs if argv[0] == SYSTEMCTL] == [
        "show"
    ]  # absent: never a start or a reload (D006)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert ["no partition instance" in r.getMessage() for r in warnings] == [True]
    record = read_record(tmp_path, DM0_RECORD)
    assert (record["kind"], record["key"]) == ("auto", "dm-0-252_0")
    assert (record["state"], record["reason"]) == (
        "NotMounted",
        "no_partition_instance",
    )
    assert record["next_step"] == ABSENT_NEXT_STEP
    assert (record["mapping"], record["mount"]) == (None, None)
    [dm0] = [view for view in views if view.kind is InstanceKind.AUTO]
    assert dm0.name == "PERSONAL"
    assert dm0.state is VolumeState.NOT_MOUNTED
    assert state.words(dm0.state, dm0.reason) == "present, not mounted yet"
    assert dm0.next_step == ABSENT_NEXT_STEP
    assert files_under(tmp_path) == files_before  # list never writes (AC-067)


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
    tmp_path: Path, ctx, host_tree, fake_runner, caplog
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
        ntfs-3g call; record state "MountedElsewhere". The record never holds
        the udisks target in ``mount`` (list and teardown would then treat the
        udisks mount as the tool's own); the outcome's reason carries it
      - the list view: state MountedElsewhere at path UDISKS_PATH, which the
        renderer shows as "mounted elsewhere (at /run/media/deck/PERSONAL1)",
        and next_step == ELSEWHERE_NEXT_STEP (AC-040)
      - no notification (not in the notify list), one NOTICE in caplog (AC-034)
    The case where udisks picks the fixed path itself is the next test.
    """
    caplog.set_level(logging.DEBUG)
    given_personal_unlocked_in_dolphin(ctx, tmp_path, host_tree)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    script_key_unit(fake_runner)
    fake_runner.on(
        TABLE_ARGV,
        Answer.from_fixture(DM0_AT_UDISKS_PATH, returncode=0),
        repeat=True,
    )

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH, Trigger.RELOAD
    )
    views = state.compute_views(
        ctx, config.load(ctx), blockdev.read_tree(ctx), mounts.table(ctx)
    )

    assert outcome.route.action is Action.MOUNT_INNER_REGISTERED
    assert outcome.state is VolumeState.MOUNTED_ELSEWHERE
    assert outcome.reason == f"mounted at {UDISKS_PATH}"
    used = {argv[0] for argv in fake_runner.argvs}
    assert used.isdisjoint({PROBE, MOUNT, NTFS3G, LOGINCTL, SYSTEMD_RUN})
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert (record["state"], record["reason"], record["mount"]) == (
        "MountedElsewhere",
        None,
        None,
    )
    assert record["next_step"] == ELSEWHERE_NEXT_STEP
    [personal] = [view for view in views if view.name == "PERSONAL"]
    assert (personal.state, personal.path) == (
        VolumeState.MOUNTED_ELSEWHERE,
        UDISKS_PATH,
    )
    shown = f"{state.words(personal.state, personal.reason)} (at {personal.path})"
    assert shown == "mounted elsewhere (at /run/media/deck/PERSONAL1)"
    assert personal.next_step == ELSEWHERE_NEXT_STEP
    [notice] = outcome_notices(caplog, "MountedElsewhere")
    assert sm_fields(notice)["SM_REASON"] == f"mounted at {UDISKS_PATH}"


# Open question 1 (work plan "Decisions on the Generator's Open Questions",
#   item 1; the owner accepted planner default 1 on 2026-10-09)
# AC-060, AC-034, ADR-0002 D4.3 (held check), DD-10 (ownership by the record)
# ROI: 24 (BV:6 x Freq:2 + Legal:0 + Defect:8)
# Behavior: findmnt list shows /dev/dm-0 at the fixed path itself, no record
#   owns a mount there -> MountedElsewhere with the fixed path, never MountedRW
# @category: edge-case
# @dependency: reconcile, mounts, state
# @complexity: medium
# @real-dependency: tmp_path records, flock
def test_udisks_at_fixed_path_is_mounted_elsewhere(
    tmp_path: Path, ctx, host_tree, fake_runner, caplog
) -> None:
    """udisks mounted PERSONAL's inner filesystem at the fixed path itself.

    Owner decision 1 (accepted 2026-10-09): a foreign mount at the fixed path
    with no owning record is ``MountedElsewhere`` with the fixed path as the
    target, never an owned ``MountedRW``. "Its own recorded target" in the
    held check means the record says this tool mounted it there
    (``mount.status`` ``mounted``, or ``pending`` from the write-ahead).
    Ownership drives teardown and ``unmount``: claiming the udisks mount would
    make a deliberate stop unmount something the tool never made.

    Given
      - the setup of the first test (no PERSONAL record), with findmnt ...
        --list --real -> the dm-0 udisks list with its target moved to
        PERSONAL_PATH (inner label PERSONAL, no leaf directory yet)
    When
      - reconcile.run(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH,
        Trigger.RELOAD), twice
    Then (pass criteria)
      - both outcomes MountedElsewhere with reason "mounted at PERSONAL_PATH";
        no probe, mount or ntfs-3g call
      - the record says MountedElsewhere and owns no mount (``mount`` null),
        so a stop or ``unmount`` has nothing of the tool's to unmount; the
        second pass does not adopt the mount either
      - one NOTICE per pass with SM_STATE=MountedElsewhere, no notification
      - ``list`` is transparent about it (owner decision 2026-10-10):
        state.compute_views(...) over the same inputs shows PERSONAL as
        MountedElsewhere at PERSONAL_PATH, words "mounted elsewhere", with the
        MountedElsewhere next step, never "mounted read-write"
    """
    caplog.set_level(logging.DEBUG)
    given_personal_unlocked_in_dolphin(ctx, tmp_path, host_tree)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    script_key_unit(fake_runner)
    fake_runner.on(TABLE_ARGV, dm0_mounted_at(PERSONAL_PATH), repeat=True)

    first = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH, Trigger.RELOAD
    )
    second = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH, Trigger.RELOAD
    )

    for outcome in (first, second):
        assert outcome.route.action is Action.MOUNT_INNER_REGISTERED
        assert (outcome.state, outcome.reason) == (
            VolumeState.MOUNTED_ELSEWHERE,
            f"mounted at {PERSONAL_PATH}",
        )
    used = {argv[0] for argv in fake_runner.argvs}
    assert used.isdisjoint({PROBE, MOUNT, NTFS3G, LOGINCTL, SYSTEMD_RUN})
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert (record["state"], record["mount"]) == ("MountedElsewhere", None)
    assert record["next_step"] == ELSEWHERE_NEXT_STEP
    assert len(outcome_notices(caplog, "MountedElsewhere")) == 2
    views = state.compute_views(
        ctx, config.load(ctx), blockdev.read_tree(ctx), mounts.table(ctx)
    )
    [personal] = [view for view in views if view.name == "PERSONAL"]
    assert (personal.state, personal.path) == (
        VolumeState.MOUNTED_ELSEWHERE,
        PERSONAL_PATH,
    )
    assert state.words(personal.state, personal.reason) == "mounted elsewhere"
    assert personal.next_step == ELSEWHERE_NEXT_STEP
