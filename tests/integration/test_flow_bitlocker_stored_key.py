"""Registered BitLocker with a stored key (PERSONAL) - integration skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "BitLocker with
Stored Key (PERSONAL)", "BitLocker Unlock and Mappings", "Key Store",
"UNLOCK_REGISTERED executor", DD-18, DD-29). Generated 2026-10-08 by the
acceptance-test-generator. Budget used: 2/3 integration for the feature
"BitLocker auto-unlock" (FR-03).

Test boundary: FakeRunner for lsblk, findmnt, cryptsetup, probe, mount, loginctl,
systemctl, systemd-run; real key file, registry, records and locks under
HostPaths(root=tmp_path) with trusted_uid = the test uid (so the 0700/0600
owner and mode checks of keystore.status run against real files).

The real tree fixtures/deck/lsblk-columns-tree.json already shows dm-0 (the
capture was taken after a Dolphin unlock). The stored-key flow therefore feeds
the FakeRunner two lsblk answers: first fixtures/synthetic/
lsblk-tree-personal-locked.json ("# synthetic: real tree minus dm-0"), then the
real tree once cryptsetup open has "created" dm-0. The host tree names dm-0
with the tool's mapping name so the dm-0 auto instance routes OWN_MAPPING.

Fixtures expected from tests/conftest.py: fake_runner, fake_platform, host_tree,
fake_kmsg, fake_clock, ctx. Skipped until steamos_mounter.reconcile exists.

The key file's path in argv is the host path under ``tmp_path``
(``keystore.key_path``), which is ``/var/lib/steamos-mounter/keys/...`` on
the Deck.
"""

import logging
from pathlib import Path

import pytest
from tests.helpers.builders import MEDIABOX, PERSONAL, registry_text
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import (
    CRYPTSETUP,
    LOGINCTL,
    LSBLK_ARGV,
    MOUNT,
    NTFS3G,
    PROBE,
    SYSTEMCTL,
    SYSTEMD_RUN,
    TABLE_ARGV,
    lock_sdb1,
    make_keys_dir,
    make_mount_base,
    make_var_run,
    read_record,
    readback_argv,
    runtime_dirs,
    script_desktop_session,
    script_lsblk,
    script_no_session,
    script_notify,
    sm_fields,
    write_key_file,
    write_registry,
)

from steamos_mounter.journal import NOTICE
from steamos_mounter.model import InstanceKind, Trigger, VolumeState
from steamos_mounter.routing import Action

reconcile = pytest.importorskip("steamos_mounter.reconcile")
keystore = pytest.importorskip("steamos_mounter.keystore")
bitlocker = pytest.importorskip("steamos_mounter.bitlocker")

PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
PERSONAL_DEVICE_PATH = f"/dev/disk/by-uuid/{PERSONAL_UUID}"
PERSONAL_RECORD = f"run/steamos-mounter/records/registered/{PERSONAL_UUID}.json"
PERSONAL_INSTANCE = (
    "dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52\\x2da297\\x2d31643c64724d"
)
KEY_UNIT = f"steamos-mounter-key@{PERSONAL_INSTANCE}.service"
MAPPING_NAME = f"steamos-mounter-{PERSONAL_UUID}"
KEY_FILE = f"var/lib/steamos-mounter/keys/{PERSONAL_UUID}.key"
DM0_SYSPATH = "/sys/devices/virtual/block/dm-0"
DM0_RECORD = "run/steamos-mounter/records/auto/dm-0-252_0.json"
TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"
CLI_ROOT = "sudo /opt/steamos-mounter/bin/steamos-mounter"
NTFS_RW_OPTIONS = "nosuid,nodev,uid=1000,gid=1000,umask=0022,windows_names"
LOCKED_TREE = Answer.from_fixture("lsblk-tree-personal-locked.json", returncode=0)
START_KEY_UNIT = (SYSTEMCTL, "start", "--no-block", "--", KEY_UNIT)
NO_SESSION_STEP = (
    f"In Desktop Mode, replug the drive or run {CLI_ROOT} mount --volume PERSONAL."
    f" Or run {CLI_ROOT} set-key PERSONAL."
)
PERMISSIONS_STEP = f"Run {CLI_ROOT} doctor, then {CLI_ROOT} set-key PERSONAL."


@pytest.fixture
def expected_open_argv(tmp_path: Path) -> tuple[str, ...]:
    """cryptsetup open with the stored key file (Design Doc "BitLocker Unlock").

    The handler never reads the key into Python: the call carries the file
    path and no stdin.
    """
    return (
        "/usr/bin/cryptsetup",
        "open",
        "--type",
        "bitlk",
        "--key-file",
        str(tmp_path / KEY_FILE),
        "/dev/sdb1",
        MAPPING_NAME,
    )


def given_personal_plugged_in_locked(ctx, tmp_path: Path, host_tree):
    """Registry with MEDIABOX and PERSONAL, the Deck's sysfs without dm-0 on sdb1.

    Returns the hook that does to sysfs what ``cryptsetup open`` does.
    """
    runtime_dirs(ctx)
    write_registry(tmp_path, registry_text([MEDIABOX, PERSONAL]))
    host_tree.add_sysfs_facts()
    host_tree.link_by_uuid(PERSONAL_UUID, "sdb1")
    make_mount_base(tmp_path)
    make_var_run(tmp_path)
    return lock_sdb1(tmp_path, MAPPING_NAME)


def key_bytes_anywhere(fake_runner, caplog, tmp_path: Path) -> bool:
    """TEST_KEY in an argv, env value, stdin, the logs, a record or the registry.

    A boolean, so a failing assertion never prints the key.
    """
    text = TEST_KEY.decode()
    in_calls = any(
        text in item for call in fake_runner.calls for item in call.argv
    ) or any(
        any(text in value for value in call.env_extra.values())
        or (call.stdin is not None and TEST_KEY in call.stdin)
        for call in fake_runner.calls
    )
    in_logs = TEST_KEY in caplog.text.encode() or any(
        text in str(sm_fields(record)) for record in caplog.records
    )
    state_files = [*(tmp_path / "run/steamos-mounter/records").rglob("*.json")]
    state_files.append(tmp_path / "etc/steamos-mounter/config.toml")
    in_files = any(TEST_KEY in path.read_bytes() for path in state_files)
    return in_calls or in_logs or in_files


# AC-010: "Given PERSONAL is registered with a valid key, when it is plugged in,
#   then it is unlocked and its inner filesystem is mounted at the fixed path
#   within the latency target, with no prompt."
# AC-059: "... its inner filesystem is mounted only at the registered fixed path.
#   The unregistered auto-mount path never mounts it."
# AC-011, AC-013 (key file layout; key never in argv, logs, records, registry)
# ROI: 99 (BV:10 x Freq:9 + Legal:0 + Defect:9)
# Behavior: container by-uuid unit plugged -> UNLOCK_REGISTERED -> key file ok ->
#   cryptsetup open --key-file -> wait_inner_ready sees dm-0 ntfs -> chain on
#   /dev/dm-0 at the fixed path -> MountedRW; dm-0 auto instance: OWN_MAPPING
# @category: core-functionality
# @dependency: reconcile, routing, keystore, bitlocker, blockdev, mounter, ntfs,
#   mounts, state, locks
# @complexity: high
# @real-dependency: tmp_path key file (0600, test uid), keys dir (0700), records,
#   sysfs slaves/holders/dm name, flock
def test_stored_key_unlocks_personal_and_mounts_inner_at_fixed_path(
    tmp_path: Path, ctx, host_tree, fake_runner, caplog, expected_open_argv
) -> None:
    """Design Doc "BitLocker with Stored Key (PERSONAL)" end to end.

    Given
      - HostPaths(root=tmp_path): registry with MEDIABOX and PERSONAL (see
        test_flow_registered_plugin.REGISTRY_TEXT), tmp_path/KEY_FILE holding
        TEST_KEY with mode 0600 in a 0700 keys dir, both owned by the test uid;
        /dev/disk/by-uuid/<PERSONAL_UUID> -> ../../sdb1; sysfs after the open:
        /sys/class/block/sdb1/holders/dm-0, /sys/block/dm-0/dm/name =
        MAPPING_NAME, /sys/class/block/dm-0/slaves/sdb1.
      - FakeRunner script:
        lsblk ... -> 1st fixtures/synthetic/lsblk-tree-personal-locked.json,
                     then fixtures/deck/lsblk-columns-tree.json (dm-0 ntfs)
        findmnt ... --list --real -> fixtures/deck/findmnt-real-list.json
        cryptsetup open --type bitlk --key-file <KEY_FILE> /dev/sdb1
            <MAPPING_NAME> -> rc 0
        ntfs-3g.probe --readwrite /dev/dm-0 -> rc 0
        mount -i -t ntfs3 -o nosuid,nodev,uid=1000,gid=1000,umask=0022,
            windows_names /dev/dm-0 /run/media/deck/PERSONAL -> rc 0
        findmnt ... --mountpoint /run/media/deck/PERSONAL
            -> fixtures/synthetic/findmnt-personal-ntfs3-rw.json
    When
      - reconcile.run(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH,
        Trigger.START)
      - reconcile.run(ctx, InstanceKind.AUTO, DM0_SYSPATH, Trigger.START)
        (the auto instance systemd starts for dm-0 once udev sees ntfs)
    Then (pass criteria)
      - first outcome: route.action == Action.UNLOCK_REGISTERED, state
        MountedRW, reason "" or "clean"; exactly one cryptsetup call equal to
        expected_open_argv with stdin None and secret flag False
      - the record was written with mapping.name == MAPPING_NAME before the
        cryptsetup call (write-ahead, DD-10)
      - record tmp_path/PERSONAL_RECORD: mapping {"name": MAPPING_NAME,
        "kname": "dm-0", "devnum": "252:0", "opened_by": "handler",
        "key_unit_invocation_id": null, "save_pending": false}; mount.device
        "/dev/dm-0", mount.target PERSONAL_PATH, mount.driver "ntfs3"
      - the only mount target in any argv is PERSONAL_PATH; nothing under
        /run/media/deck/PERSONAL-2 or a label-derived path (AC-059)
      - second outcome: route.action == Action.OWN_MAPPING; no new mount,
        probe or cryptsetup call; tmp_path/DM0_RECORD does not exist
      - TEST_KEY never appears in any recorded argv, env value, stdin, caplog
        text, the record or the registry (AC-013; the full sweep lives in
        tests/contract/test_secrets.py)
      - no systemctl start of KEY_UNIT, no loginctl call, no notification
    """
    caplog.set_level(logging.DEBUG)
    opened = given_personal_plugged_in_locked(ctx, tmp_path, host_tree)
    write_key_file(tmp_path, PERSONAL_UUID, TEST_KEY)
    written_ahead = []

    def cryptsetup_opens(command) -> None:
        written_ahead.append(read_record(tmp_path, PERSONAL_RECORD)["mapping"])
        opened(command)

    fake_runner.on(LSBLK_ARGV, LOCKED_TREE)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, "findmnt-real-list.json")
    fake_runner.on(CRYPTSETUP, Answer(), hook=cryptsetup_opens)
    fake_runner.on(PROBE, Answer())
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(
        readback_argv(PERSONAL_PATH),
        Answer.from_fixture("findmnt-personal-ntfs3-rw.json", returncode=0),
    )

    first = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH, Trigger.START
    )
    first_pass = len(fake_runner.calls)
    second = reconcile.run(ctx, InstanceKind.AUTO, DM0_SYSPATH, Trigger.START)

    assert first.route.action is Action.UNLOCK_REGISTERED
    assert first.state is VolumeState.MOUNTED_RW
    assert first.reason in {None, "", "clean"}
    [open_call] = [call for call in fake_runner.calls if call.argv[0] == CRYPTSETUP]
    assert open_call.argv == expected_open_argv
    assert (open_call.stdin, open_call.secret_stdin) == (None, False)
    assert [mapping["name"] for mapping in written_ahead] == [MAPPING_NAME]  # DD-10
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert record["mapping"] == {
        "name": MAPPING_NAME,
        "kname": "dm-0",
        "devnum": "252:0",
        "opened_by": "handler",
        "key_unit_invocation_id": None,
        "save_pending": False,
    }
    assert (
        record["mount"]["device"],
        record["mount"]["target"],
        record["mount"]["driver"],
    ) == ("/dev/dm-0", PERSONAL_PATH, "ntfs3")
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
    assert under_base == {PERSONAL_PATH}  # AC-059
    assert second.route.action is Action.OWN_MAPPING
    assert fake_runner.argvs[first_pass:] == [LSBLK_ARGV]
    assert not (tmp_path / DM0_RECORD).exists()
    assert not key_bytes_anywhere(fake_runner, caplog, tmp_path)
    used = {argv[0] for argv in fake_runner.argvs}
    assert used.isdisjoint({SYSTEMCTL, LOGINCTL, SYSTEMD_RUN})


# AC-014: "Given a wrong or missing stored key, when the volume is plugged in,
#   then the stored key is tried once, with no retry loop. list and journald
#   record the unlock failure. The volume stays locked unless the FR-22 dialog
#   succeeds. In Desktop Mode, the FR-22 dialog replaces the 'unlock failed, run
#   set-key' notification for that event."
# AC-075: no Desktop Mode session -> no dialog anywhere, "needs a key"
# DD-18: wrong owner or mode -> NeedsKey reason key_permissions, no dialog
# ROI: 40 (BV:8 x Freq:4 + Legal:0 + Defect:8)
# Behavior: UNLOCK_REGISTERED -> keystore.status -> one open attempt at most ->
#   NeedsKey with the reason -> key unit started (desktop) or nothing (no
#   session / permissions) -> notification only for key_permissions
# @category: core-functionality
# @dependency: reconcile, keystore, bitlocker, session, systemd, notify, state
# @complexity: high
# @real-dependency: tmp_path key file and modes, records, flock
@pytest.mark.parametrize(
    "case",
    ["rejected", "missing", "bad-permissions", "no-session"],
)
def test_stored_key_failure_tried_once_then_key_unit_or_needs_key(
    case: str, tmp_path: Path, ctx, host_tree, fake_runner, caplog
) -> None:
    """One attempt, then NeedsKey; the key unit replaces the notification.

    Given (per case)
      - "rejected": key file present and 0600; cryptsetup open -> rc 2;
        loginctl fixtures give the Desktop verdict
      - "missing": no key file; loginctl -> Desktop
      - "bad-permissions": key file mode 0644; loginctl -> Desktop
      - "no-session": key file present, cryptsetup -> rc 2; loginctl show-user
        deck -p Display -> "Display=" (empty, same as absent) -> verdict none
    When
      - reconcile.run(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH,
        Trigger.START)
    Then (pass criteria)
      - cryptsetup open is called exactly once for "rejected" and "no-session",
        never for "missing" and "bad-permissions" (AC-014: no retry loop)
      - outcome.state == VolumeState.NEEDS_KEY with reason
        "stored_key_rejected" / "stored_key_missing" / "key_permissions" /
        "no_session" respectively; the record carries the same reason
      - "rejected" and "missing": one systemctl start --no-block KEY_UNIT call
        and no notify-send call (the dialog replaces it, AC-014, AC-046)
      - "bad-permissions": no systemctl start; one notify-send call naming
        PERSONAL whose body points to doctor and then set-key (DD-18, DD-19)
      - "no-session": no systemctl start, no notify-send (Game Mode notification
        deferred, AC-074); state.next_step says "In Desktop Mode, replug ... or
        ... mount --volume PERSONAL ... or ... set-key PERSONAL" (AC-075)
      - no mount, probe or ntfs-3g call in any case; the key file is byte-for-
        byte unchanged where it existed, and "missing" leaves no key file
      - caplog has a NOTICE or WARNING entry with SM_STATE=NeedsKey and the
        reason (AC-041); TEST_KEY appears nowhere in the log
    """
    caplog.set_level(logging.DEBUG)
    given_personal_plugged_in_locked(ctx, tmp_path, host_tree)
    key_file = tmp_path / KEY_FILE
    if case == "missing":
        make_keys_dir(tmp_path)
    else:
        write_key_file(
            tmp_path,
            PERSONAL_UUID,
            TEST_KEY,
            mode=0o644 if case == "bad-permissions" else 0o600,
        )
    script_lsblk(fake_runner, "lsblk-tree-personal-locked.json")
    fake_runner.on(CRYPTSETUP, Answer(returncode=2))
    if case == "no-session":
        script_no_session(fake_runner)
    else:
        script_desktop_session(fake_runner)
    fake_runner.on(START_KEY_UNIT, Answer())
    script_notify(fake_runner)
    expected_reason = {
        "rejected": "stored_key_rejected",
        "missing": "stored_key_missing",
        "bad-permissions": "key_permissions",
        "no-session": "no_session",
    }[case]

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH, Trigger.START
    )

    opens = [argv for argv in fake_runner.argvs if argv[0] == CRYPTSETUP]
    tried = 1 if case in {"rejected", "no-session"} else 0
    assert len(opens) == tried  # AC-014: no retry loop
    assert (outcome.state, outcome.reason) == (VolumeState.NEEDS_KEY, expected_reason)
    record = read_record(tmp_path, PERSONAL_RECORD)
    assert (record["state"], record["reason"]) == ("NeedsKey", expected_reason)
    starts = [argv for argv in fake_runner.argvs if argv[:2] == (SYSTEMCTL, "start")]
    notices = [argv for argv in fake_runner.argvs if argv[0] == SYSTEMD_RUN]
    if case in {"rejected", "missing"}:
        assert starts == [START_KEY_UNIT]
        assert notices == []  # the dialog replaces it (AC-014, AC-046)
    elif case == "bad-permissions":
        assert starts == []
        [notice] = notices
        assert "PERSONAL needs a key" in notice
        assert notice[-1].endswith(PERMISSIONS_STEP)  # DD-18: doctor, then set-key
        assert record["next_step"] == PERMISSIONS_STEP
    else:
        assert (starts, notices) == ([], [])  # Game Mode notice deferred (AC-074)
        assert record["next_step"] == NO_SESSION_STEP  # AC-075
        # The Design Doc's "list and scan Output" example, word for word.
        assert record["warning"] == (
            "The stored key did not work, and there was no Desktop Mode session"
            " for the key dialog."
        )
    used = {argv[0] for argv in fake_runner.argvs}
    assert used.isdisjoint({MOUNT, PROBE, NTFS3G})
    if case == "missing":
        assert not key_file.exists()  # nothing invents a key file
    else:
        assert key_file.read_bytes() == TEST_KEY
    logged = [
        r
        for r in caplog.records
        if r.levelno in {logging.WARNING, NOTICE}
        and sm_fields(r).get("SM_STATE") == "NeedsKey"
    ]
    assert {sm_fields(r)["SM_REASON"] for r in logged} == {expected_reason}
    assert not key_bytes_anywhere(fake_runner, caplog, tmp_path)
