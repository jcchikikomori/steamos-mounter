"""Fallback key dialog flow (FR-22, PERSONAL) - integration skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "Key Dialog Unit",
"Key Dialog Path (Stored Key Missing or Rejected, Desktop Mode)", "Key unit
interplay" (ADR-0005 D5.2, J001), DD-19, DD-21, "Required Specific Tests" 1).
Generated 2026-10-08 by the acceptance-test-generator. Budget used: 3/3
integration for the feature "fallback key dialog" (FR-22).

Test boundary: FakeRunner for loginctl, systemctl, systemd-run (dialog and
notification transports), cryptsetup, lsblk, findmnt, probe, mount; real
/proc/net/unix, /proc/<pid>/fd and /proc/<pid>/cgroup files under
HostPaths(root=tmp_path) (synthetic fixtures, Design Doc "Fixtures"); real
flock in tmp_path for the J001 race; FakeClock for the 120 s and 60 s timers.

Fixtures expected from tests/conftest.py: fake_runner, fake_platform, host_tree,
fake_kmsg, fake_clock, ctx (with invocation_id set, as a unit would have).
Skipped until steamos_mounter.keyunit exists.
"""

import logging
import os
import threading
from pathlib import Path

import pytest
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import (
    CRYPTSETUP,
    LOGINCTL,
    MOUNT,
    PROBE,
    SYSTEMCTL,
    TABLE_ARGV,
    key_unit_show,
    read_record,
    readback_argv,
    script_key_unit,
    script_lsblk,
    sm_fields,
)
from tests.helpers.key_dialog import (
    DIALOG_LOCK,
    DIALOG_STOP,
    ENTERED,
    NO,
    SESSION_ENV,
    SHOW_ENVIRONMENT,
    STOP_KEY_UNIT,
    YES,
    given_key_unit_started,
    is_notify,
    is_password,
    is_save,
    key_found_outside,
    script_key_unit_flow,
)

from steamos_mounter import locks, state
from steamos_mounter.model import InstanceKind, Trigger, VolumeState
from steamos_mounter.sensitive import live_secrets

keyunit = pytest.importorskip("steamos_mounter.keyunit")
reconcile = pytest.importorskip("steamos_mounter.reconcile")
dialog = pytest.importorskip("steamos_mounter.dialog")

PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
PERSONAL_DEVICE_PATH = f"/dev/disk/by-uuid/{PERSONAL_UUID}"
PERSONAL_RECORD = f"run/steamos-mounter/records/registered/{PERSONAL_UUID}.json"
PERSONAL_INSTANCE = (
    "dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52\\x2da297\\x2d31643c64724d"
)
REGISTERED_UNIT = f"steamos-mounter@{PERSONAL_INSTANCE}.service"
KEY_UNIT = f"steamos-mounter-key@{PERSONAL_INSTANCE}.service"
DIALOG_UNIT = f"steamos-mounter-dialog-{PERSONAL_UUID}"
MAPPING_NAME = f"steamos-mounter-{PERSONAL_UUID}"
KEY_FILE = f"var/lib/steamos-mounter/keys/{PERSONAL_UUID}.key"
VOLUME_LOCK = f"run/steamos-mounter/locks/volume-{PERSONAL_UUID}.lock"
KEY_UNIT_INVOCATION_ID = "0f6c9c1e5c7a4c51a0a5f3f3b2b6d7e8"
TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"
DM0_NAME = "sys/block/dm-0/dm/name"
UDISKS_NAME = "PAT4T4SHUAWEI_PERSONAL_4_3_2024"  # DM_NAME in udev-dm-0.txt
CLI_ROOT = "sudo /opt/steamos-mounter/bin/steamos-mounter"
CANCELLED_STEP = (
    f"Replug the drive or run {CLI_ROOT} mount --volume PERSONAL when you want to"
    " unlock it."
)
RELOAD_THREAD = "delegated-reload"
RACE_WAIT = 5.0  # wall seconds for one side of the race to reach the other
JOIN_WAIT = 10.0
PASSWORD_PROMPT = (
    "PERSONAL is locked. Its stored key did not work. Enter the BitLocker "
    "password or the 48-digit recovery key."
)
SAVE_PROMPT = (
    "Save this key for next time? PERSONAL will then unlock at plug-in without asking."
)


@pytest.fixture
def expected_password_argv() -> tuple[str, ...]:
    """Dialog transport argv, byte for byte from Design Doc "Transport"."""
    return (
        "/usr/bin/systemd-run",
        "--user",
        "--pipe",
        "--wait",
        "--quiet",
        "--collect",
        f"--unit={DIALOG_UNIT}",
        "--property=SuccessExitStatus=1",
        "--property=RuntimeMaxSec=130",
        "--property=UnsetEnvironment=WAYLAND_DISPLAY",
        "--setenv=DISPLAY=:0",
        "--setenv=QT_QPA_PLATFORM=xcb",
        "/usr/bin/kdialog",
        "--title",
        "steamos-mounter",
        "--password",
        PASSWORD_PROMPT,
    )


@pytest.fixture
def expected_save_argv() -> tuple[str, ...]:
    """Save question argv: no SuccessExitStatus=1 (DD-21), RuntimeMaxSec=70."""
    return (
        "/usr/bin/systemd-run",
        "--user",
        "--pipe",
        "--wait",
        "--quiet",
        "--collect",
        f"--unit={DIALOG_UNIT}",
        "--property=RuntimeMaxSec=70",
        "--property=UnsetEnvironment=WAYLAND_DISPLAY",
        "--setenv=DISPLAY=:0",
        "--setenv=QT_QPA_PLATFORM=xcb",
        "/usr/bin/kdialog",
        "--title",
        "steamos-mounter",
        "--yesno",
        SAVE_PROMPT,
    )


def personal_record(tmp_path: Path) -> dict:
    return read_record(tmp_path, PERSONAL_RECORD)


def lock_held(ctx, relative: str) -> bool:
    """True when the lock file at ``relative`` is held by someone now."""
    if relative == DIALOG_LOCK:
        take = locks.dialog_lock(ctx, timeout=0)
    else:
        take = locks.volume_lock(ctx, PERSONAL_UUID, timeout=0)
    try:
        with take:
            return False
    except locks.LockTimeout:
        return True


# AC-070: "... a password dialog naming the volume appears in that session ..."
# AC-071: "Given the owner enters a key that works, then the volume is unlocked
#   and its inner filesystem is mounted at the registered fixed path ..."
# AC-072: "... a separate 'Save this key for next time?' question appears with
#   Yes and No. On Yes, the key is stored under the AC-011 rules ..."
# AC-076, AC-077 (session check before the dialog; key never on argv or in logs)
# ROI: 45 (BV:9 x Freq:4 + Legal:0 + Defect:9)
# Behavior: record NeedsKey stored_key_rejected -> keyunit.run: session check
#   with display -> dialog lock -> password dialog (entered) -> volume lock,
#   cryptsetup open --key-file=- -> record opened_by key-unit + save_pending ->
#   request_reconcile -> registered RELOAD mounts inner -> save question Yes ->
#   key file 0600 written, save_pending cleared
# @category: core-functionality
# @dependency: keyunit, session, dialog, locks, bitlocker, state, systemd,
#   keystore, reconcile, mounter, sensitive
# @complexity: high
# @real-dependency: tmp_path /proc files (X0 listener inode 2205399, fd link,
#   cgroup scope), flock (dialog lock + volume lock), key file, records
def test_rejected_key_dialog_entered_reload_mounts_and_yes_saves(
    tmp_path: Path,
    ctx,
    host_tree,
    fake_runner,
    caplog,
    expected_password_argv,
    expected_save_argv,
) -> None:
    """Design Doc "Key Dialog Path" happy path through the save question.

    Given
      - HostPaths(root=tmp_path): registry with PERSONAL; record
        tmp_path/PERSONAL_RECORD in state NeedsKey reason stored_key_rejected
        (as test_flow_bitlocker_stored_key leaves it); no key file;
        /proc/net/unix from fixtures/synthetic/proc-net-unix-x0-listening.txt
        (path row /tmp/.X11-unix/X0, flags 00010000, state 01, inode 2205399),
        /proc/4242/fd/7 -> "socket:[2205399]", /proc/4242/cgroup ending in
        "/session-5.scope"; ctx.invocation_id == KEY_UNIT_INVOCATION_ID.
      - FakeRunner script:
        loginctl show-user deck -p Display -> fixtures/deck/loginctl-user-deck.txt
        loginctl show-seat seat0 -p ActiveSession -> "ActiveSession=5"
        loginctl show-session 5 -p Name,Seat,Active,Remote,Class,Type,State,
            Desktop,Scope,Display,Service,VTNr
            -> fixtures/deck/loginctl-session-5-properties.txt
        systemctl --user show-environment (user 1000, log_output False)
            -> "DISPLAY=:0\\nOTHER=dropped\\n"
        systemd-run ... kdialog --password ... -> rc 0, stdout TEST_KEY + b"\\n"
            (secret_stdout, cap 256)
        cryptsetup open --type bitlk --key-file=- /dev/sdb1 <MAPPING_NAME>
            -> rc 0 (stdin == TEST_KEY, flagged secret in the log)
        systemctl show ... <REGISTERED_UNIT> -> ActiveState=active
        systemctl reload --no-block <REGISTERED_UNIT> -> rc 0
        systemd-run ... kdialog --yesno ... -> rc 0 (Yes)
        plus the stored-key flow's lsblk / probe / mount / findmnt answers for
        the RELOAD pass on /dev/dm-0
    When
      - keyunit.run(ctx, PERSONAL_DEVICE_PATH)
      - reconcile.run(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH,
        Trigger.RELOAD) (what the requested reload runs; the key unit is still
        active with KEY_UNIT_INVOCATION_ID)
    Then (pass criteria)
      - the password transport call equals expected_password_argv, runs as
        uid 1000 gid 1000 with env_extra exactly {XDG_RUNTIME_DIR:
        /run/user/1000, DBUS_SESSION_BUS_ADDRESS: unix:path=/run/user/1000/bus}
        and secret_stdout True; it comes after the three loginctl calls and the
        show-environment call (AC-076)
      - exactly one cryptsetup open with stdin TEST_KEY (one trailing newline
        stripped) and no --key-file path; TEST_KEY appears in no argv, env
        value, caplog text, record or registry (AC-077)
      - after the open and before the reload request the record reads
        mapping.opened_by "key-unit", mapping.key_unit_invocation_id ==
        KEY_UNIT_INVOCATION_ID, mapping.save_pending true, dialog.outcome
        "unlocked"
      - the RELOAD pass mounts /dev/dm-0 at PERSONAL_PATH (MountedRW) and makes
        no systemctl stop of KEY_UNIT (record says key-unit with the active
        InvocationID, ADR-0005 D5.2)
      - the save transport call equals expected_save_argv and comes after the
        second session check; tmp_path/KEY_FILE then holds exactly TEST_KEY
        with mode 0600 in a 0700 dir (AC-011), record dialog.outcome "saved",
        mapping.save_pending false
      - the dialog lock locks/dialog.lock and the volume lock are both free at
        the end; no notify-send call (the dialog replaced it)
    """
    caplog.set_level(logging.DEBUG)
    opened = given_key_unit_started(ctx, tmp_path, host_tree)
    at_reload = []
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, "findmnt-real-list.json")
    fake_runner.on(PROBE, Answer())
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(
        readback_argv(PERSONAL_PATH),
        Answer.from_fixture("findmnt-personal-ntfs3-rw.json", returncode=0),
    )
    script_key_unit(fake_runner, key_unit_show("active", KEY_UNIT_INVOCATION_ID))
    script_key_unit_flow(
        fake_runner,
        opened,
        save=YES,
        hooks={"reload": lambda _c: at_reload.append(personal_record(tmp_path))},
    )

    keyunit.run(ctx, PERSONAL_DEVICE_PATH)
    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH, Trigger.RELOAD
    )

    calls = fake_runner.calls
    argvs = fake_runner.argvs
    [password] = [call for call in calls if is_password(call)]
    assert password.argv == expected_password_argv
    assert (password.user, password.group) == (1000, 1000)
    assert dict(password.env_extra) == SESSION_ENV
    assert password.secret_stdout
    assert [argv[:2] for argv in argvs[:4]] == [
        (LOGINCTL, "show-user"),
        (LOGINCTL, "show-seat"),
        (LOGINCTL, "show-session"),
        SHOW_ENVIRONMENT[:2],
    ]  # AC-076: the session check comes first
    assert argvs.index(password.argv) > 3
    [open_call] = [call for call in calls if call.argv[0] == CRYPTSETUP]
    assert "--key-file=-" in open_call.argv
    assert "--key-file" not in open_call.argv  # no key file path
    stdin_is_key = open_call.stdin == TEST_KEY
    assert stdin_is_key
    assert not key_found_outside(fake_runner, caplog, tmp_path)  # AC-077
    [then] = at_reload
    assert then["mapping"]["opened_by"] == "key-unit"
    assert then["mapping"]["key_unit_invocation_id"] == KEY_UNIT_INVOCATION_ID
    assert then["mapping"]["save_pending"] is True
    assert then["dialog"]["outcome"] == "unlocked"
    assert outcome.state is VolumeState.MOUNTED_RW
    final = personal_record(tmp_path)
    assert (final["state"], final["mount"]["target"]) == ("MountedRW", PERSONAL_PATH)
    assert [argv for argv in argvs if argv[:2] == (SYSTEMCTL, "stop")] == []
    [save] = [call.argv for call in calls if is_save(call)]
    assert save == expected_save_argv
    second_check = max(i for i, argv in enumerate(argvs) if argv == SHOW_ENVIRONMENT)
    assert argvs.index(save) > second_check > argvs.index(open_call.argv)
    key_file = tmp_path / KEY_FILE
    stored_is_key = key_file.read_bytes() == TEST_KEY
    assert stored_is_key
    assert key_file.stat().st_mode & 0o777 == 0o600
    assert key_file.parent.stat().st_mode & 0o777 == 0o700
    assert final["dialog"]["outcome"] == "saved"
    assert final["mapping"]["save_pending"] is False
    assert not lock_held(ctx, DIALOG_LOCK)
    assert not lock_held(ctx, VOLUME_LOCK)
    assert [call for call in calls if is_notify(call)] == []


# AC-073: "Given the owner cancels the dialog or enters a wrong key, then the
#   volume stays locked for that plug-in. Nothing is stored, journald logs the
#   outcome, and list shows it as unlock cancelled or unlock failed."
# DD-19 / K2: notification for a rejected typed key and for "dialog failed",
#   never for a cancel. ADR-0005 D3.5: other exit status is "failed", never
#   "cancelled". Design Doc "Outcome mapping": 120 s timer -> dialog.stop.
# ROI: 25 (BV:6 x Freq:3 + Legal:0 + Defect:7)
# Behavior: dialog outcome -> state and record -> notification policy -> no key
#   file in every case
# @category: edge-case
# @dependency: keyunit, dialog, bitlocker, notify, state, locks
# @complexity: medium
# @real-dependency: tmp_path /proc files, flock, records; FakeClock for timeout
@pytest.mark.parametrize(
    "case",
    ["cancel", "wrong-key", "dialog-failed", "timeout"],
)
def test_dialog_cancel_wrong_key_failed_and_timeout_store_nothing(
    case: str,
    tmp_path: Path,
    ctx,
    host_tree,
    fake_runner,
    fake_clock,
    caplog,
) -> None:
    """Every non-success dialog outcome leaves PERSONAL locked and unsaved.

    Given (same session setup as the happy path; per case the dialog answer)
      - "cancel": systemd-run ... --password -> rc 0, empty stdout
      - "wrong-key": rc 0 with TEST_KEY; cryptsetup open -> rc 2
      - "dialog-failed": rc 134 (kdialog abort on a bad display)
      - "timeout": the FakeRunner reports timed_out after PASSWORD_TIMEOUT
        (FakeClock advanced past 120 s)
    When
      - keyunit.run(ctx, PERSONAL_DEVICE_PATH)
    Then (pass criteria)
      - record state and dialog.outcome: "cancel" -> UnlockCancelled /
        "cancelled"; "wrong-key" -> UnlockFailed / "unlock-failed";
        "dialog-failed" -> NeedsKey reason dialog_failed / "failed";
        "timeout" -> UnlockCancelled / "timed-out"
      - cryptsetup open is called only for "wrong-key", exactly once
      - "timeout" adds one call "systemctl --user stop --no-block <DIALOG_UNIT>"
        as uid 1000 (dialog.stop)
      - notify-send transport: one call for "wrong-key" and "dialog-failed"
        (body names PERSONAL and the next step), none for "cancel" and
        "timeout" (DD-19)
      - no save question call, tmp_path/KEY_FILE absent, mapping null in the
        record, no request_reconcile (no systemctl reload) in any case
      - state.words(...) for the record gives "unlock cancelled at the key
        dialog" or "unlock failed" (or "needs a key: ..." for "dialog-failed")
        and the exact next step of each case, naming mount --volume PERSONAL
        or set-key PERSONAL (AC-040, AC-073)
      - caplog: one entry per case with SM_EVENT=key and the outcome: WARNING,
        or ERROR for "wrong-key" (Design Doc "Logging and Secret Handling":
        ERROR for unlock failed); TEST_KEY absent from caplog, records and
        the FakeRunner log
    """
    caplog.set_level(logging.DEBUG)
    opened = given_key_unit_started(ctx, tmp_path, host_tree)

    def timer_runs_out(_command) -> None:
        fake_clock.advance(dialog.PASSWORD_TIMEOUT + 1)

    password, open_rc, hooks = {
        "cancel": (Answer(), 0, None),
        "wrong-key": (ENTERED, 2, None),
        "dialog-failed": (Answer(returncode=134), 0, None),
        "timeout": (Answer.timeout(), 0, {"password": timer_runs_out}),
    }[case]
    expected_state, expected_outcome, expected_words = {
        "cancel": (
            "UnlockCancelled",
            "cancelled",
            "unlock cancelled at the key dialog",
        ),
        "wrong-key": ("UnlockFailed", "unlock-failed", "unlock failed"),
        "dialog-failed": (
            "NeedsKey",
            "failed",
            "needs a key: key dialog could not be shown",
        ),
        "timeout": (
            "UnlockCancelled",
            "timed-out",
            "unlock cancelled at the key dialog: key dialog timed out",
        ),
    }[case]
    expected_step = {
        "cancel": CANCELLED_STEP,
        "wrong-key": (
            f"Replug the drive or run {CLI_ROOT} mount --volume PERSONAL to try"
            f" again, or run {CLI_ROOT} set-key PERSONAL."
        ),
        "dialog-failed": f"Run {CLI_ROOT} set-key PERSONAL, or unlock it in Dolphin.",
        "timeout": CANCELLED_STEP,
    }[case]
    script_key_unit_flow(
        fake_runner, opened, password=password, open_rc=open_rc, hooks=hooks
    )

    keyunit.run(ctx, PERSONAL_DEVICE_PATH)

    saved = personal_record(tmp_path)
    assert (saved["state"], saved["dialog"]["outcome"]) == (
        expected_state,
        expected_outcome,
    )
    opens = [argv for argv in fake_runner.argvs if argv[0] == CRYPTSETUP]
    assert len(opens) == (1 if case == "wrong-key" else 0)
    stops = [call for call in fake_runner.calls if call.argv == DIALOG_STOP]
    assert len(stops) == (1 if case == "timeout" else 0)
    assert all((call.user, call.group) == (1000, 1000) for call in stops)
    notices = [call.argv for call in fake_runner.calls if is_notify(call)]
    if case in {"wrong-key", "dialog-failed"}:
        [notice] = notices  # DD-19, K2
        assert "PERSONAL" in notice[-2]
        assert notice[-1].endswith(saved["next_step"])
    else:
        assert notices == []  # never for a cancel (DD-19)
    assert [call for call in fake_runner.calls if is_save(call)] == []
    assert not (tmp_path / KEY_FILE).exists()
    assert saved["mapping"] is None
    assert [argv for argv in fake_runner.argvs if argv[1:2] == ("reload",)] == []
    volume_state = VolumeState(saved["state"])
    assert state.words(volume_state, saved["reason"]) == expected_words
    assert saved["next_step"] == expected_step  # AC-040, AC-073
    entries = [
        r
        for r in caplog.records
        if sm_fields(r).get("SM_EVENT") == "key"
        and sm_fields(r).get("SM_STATE") == expected_state
        and sm_fields(r).get("SM_REASON") == saved["reason"]
    ]
    # Design Doc "Logging": WARNING for cancel and needs a key, ERROR for unlock failed.
    expected_level = logging.ERROR if case == "wrong-key" else logging.WARNING
    assert [r.levelno for r in entries] == [expected_level]
    assert not key_found_outside(fake_runner, caplog, tmp_path)
    assert all(TEST_KEY not in secret for secret in live_secrets())


# Design Doc "Required Specific Tests" 1, J001 race (review carry-over):
#   "two threads with real flock in tmp_path. The key unit holds the per-volume
#   lock between cryptsetup open (fake) and the record write; a reconcile
#   (triggered as a delegated reload ...) blocks on the lock, then reads the
#   record, sees opened_by = key-unit with the active key unit's InvocationID,
#   and does not stop the key unit. Variant: a foreign mapping name -> it does
#   stop it."
# AC-035 (one mount under concurrency), ADR-0005 D5.2, AC-060 (Dolphin variant)
# ROI: 30 (BV:7 x Freq:3 + Legal:0 + Defect:9)
# Behavior: thread A (key unit) holds the volume lock across open + record write;
#   thread B (delegated RELOAD) blocks, then reads the fresh record and decides
#   whether to stop the key unit
# @category: integration
# @dependency: keyunit, reconcile, locks, state, bitlocker, systemd
# @complexity: high
# @real-dependency: flock on tmp_path/VOLUME_LOCK across two threads, records
@pytest.mark.parametrize("opener", ["key-unit", "foreign"])
def test_j001_delegated_reload_waits_for_key_unit_lock_then_decides(
    opener: str,
    tmp_path: Path,
    ctx,
    host_tree,
    fake_runner,
    monkeypatch,
) -> None:
    """Real-flock race between the key unit's unlock and a delegated reload.

    Given
      - the happy-path setup; the FakeRunner's cryptsetup open blocks on a
        threading.Barrier until thread B has tried the volume lock (observed
        through a FakeRunner hook on the first findmnt call of thread B or a
        lock-wait probe on tmp_path/VOLUME_LOCK with LOCK_NB)
      - "key-unit": the key unit opens the mapping (MAPPING_NAME) and records
        opened_by "key-unit" with KEY_UNIT_INVOCATION_ID
      - "foreign": dm-0 carries a udisks label-derived name and the record says
        opened_by "other" (a Dolphin unlock that raced the dialog)
      - systemctl show <KEY_UNIT> -> ActiveState=active, InvocationID=
        KEY_UNIT_INVOCATION_ID
    When
      - thread A: keyunit.run(ctx, PERSONAL_DEVICE_PATH) up to and including
        the record write (the save question answers No to end the thread)
      - thread B: reconcile.run(ctx, InstanceKind.REGISTERED,
        PERSONAL_DEVICE_PATH, Trigger.RELOAD), started while A holds the lock
    Then (pass criteria)
      - thread B's first record read happens after thread A released the lock
        (B observes mapping.opened_by already set: B's probe and stop hooks
        read A's post-open record)
      - exactly one mount of /dev/dm-0 at PERSONAL_PATH across both threads
        (AC-035); the volume lock is free at the end
      - "key-unit": no "systemctl stop" of KEY_UNIT in the log
      - "foreign": exactly one "systemctl stop --no-block <KEY_UNIT>" call
        (closes the dialog after a Dolphin unlock, ADR-0005 D5.2)
      - the test finishes within 10 s of wall time (no deadlock; join both
        threads with a timeout and fail if alive). Nothing here advances the
        FakeClock, so a FakeClock bound would always hold and is not asserted.
      - observed order: for "key-unit", B's probe sees A's post-open record
        (dialog "unlocked", or already "not-saved", never "entered";
        opened_by "key-unit" with A's InvocationID); for
        "foreign", B's stop of KEY_UNIT sees A's last write (mapping null)
    """
    opened = given_key_unit_started(ctx, tmp_path, host_tree)
    start_b = threading.Event()
    b_blocked = threading.Event()
    met = threading.Barrier(2, timeout=RACE_WAIT)
    seen: dict[str, bool] = {}
    b_saw: dict[str, dict] = {}
    outcomes = []
    errors: list[BaseException] = []
    real_try_lock = locks._try_lock

    def spying_try_lock(fd: int) -> bool:
        got = real_try_lock(fd)
        on_volume_lock = os.readlink(f"/proc/self/fd/{fd}").endswith(VOLUME_LOCK)
        if (
            not got
            and on_volume_lock
            and threading.current_thread().name == (RELOAD_THREAD)
        ):
            b_blocked.set()
        return got

    def b_probes(_command) -> None:
        b_saw["at_probe"] = personal_record(tmp_path)

    def b_stops_key_unit(_command) -> None:
        b_saw["at_stop"] = personal_record(tmp_path)

    def a_opens_while_b_arrives(command) -> None:
        opened(command)
        if opener == "foreign":  # Dolphin's mapping, not the tool's
            (tmp_path / DM0_NAME).write_text(f"{UDISKS_NAME}\n", encoding="utf-8")
        start_b.set()
        met.wait()  # B is at its key unit check, about to take the volume lock
        seen["b_blocked"] = b_blocked.wait(RACE_WAIT)

    def b_reaches_key_unit_check(_command) -> None:
        met.wait()

    monkeypatch.setattr(locks, "_try_lock", spying_try_lock)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, "findmnt-real-list.json")
    fake_runner.on(PROBE, Answer(), hook=b_probes)
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(
        readback_argv(PERSONAL_PATH),
        Answer.from_fixture("findmnt-personal-ntfs3-rw.json", returncode=0),
    )
    fake_runner.on(
        lambda command: (
            tuple(command.argv[:2]) == (SYSTEMCTL, "show")
            and command.argv[-1] == KEY_UNIT
        ),
        key_unit_show("active", KEY_UNIT_INVOCATION_ID),
        hook=b_reaches_key_unit_check,
    )
    fake_runner.on(STOP_KEY_UNIT, Answer(), hook=b_stops_key_unit)
    script_key_unit_flow(
        fake_runner,
        opened,
        save=NO,
        open_rc=0 if opener == "key-unit" else 5,
        hooks={"open": a_opens_while_b_arrives},
    )

    def thread_a() -> None:
        try:
            keyunit.run(ctx, PERSONAL_DEVICE_PATH)
        except BaseException as error:  # noqa: BLE001 - reported by the test below
            errors.append(error)

    def thread_b() -> None:
        try:
            if start_b.wait(RACE_WAIT):
                outcomes.append(
                    reconcile.run(
                        ctx,
                        InstanceKind.REGISTERED,
                        PERSONAL_DEVICE_PATH,
                        Trigger.RELOAD,
                    )
                )
        except BaseException as error:  # noqa: BLE001 - reported by the test below
            errors.append(error)

    threads = [
        threading.Thread(target=thread_a, name="key-unit"),
        threading.Thread(target=thread_b, name=RELOAD_THREAD),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(JOIN_WAIT)

    assert [thread.is_alive() for thread in threads] == [False, False]  # no deadlock
    assert errors == []
    assert seen == {"b_blocked": True}  # B waited on A's volume lock
    argvs = fake_runner.argvs
    # What B read came from A's last write under the lock, not from before it:
    # B never writes ``dialog``, and its own mapping write comes after the stop.
    at_probe = b_saw["at_probe"]
    [outcome] = outcomes
    assert outcome.state is VolumeState.MOUNTED_RW
    mounts = [argv for argv in argvs if argv[0] == MOUNT]
    assert [(argv[-2], argv[-1]) for argv in mounts] == [("/dev/dm-0", PERSONAL_PATH)]
    assert not lock_held(ctx, VOLUME_LOCK)
    stops = [argv for argv in argvs if argv[:2] == (SYSTEMCTL, "stop")]
    final = personal_record(tmp_path)
    if opener == "key-unit":
        assert stops == []  # the save question survives (ADR-0005 D5.2)
        # A's post-open write landed ("unlocked"); A's save outcome may land too,
        # between B's record read and B's mount pass (two lock holds in B).
        assert at_probe["dialog"]["outcome"] in {"unlocked", "not-saved"}
        assert at_probe["mapping"]["opened_by"] == "key-unit"
        assert at_probe["mapping"]["key_unit_invocation_id"] == (KEY_UNIT_INVOCATION_ID)
        assert final["mapping"]["opened_by"] == "key-unit"
    else:
        assert stops == [STOP_KEY_UNIT]  # closes the dialog after a Dolphin unlock
        assert b_saw["at_stop"]["mapping"] is None  # A's _without_mapping landed
        assert at_probe["dialog"]["outcome"] == "entered"  # A recorded no failure
        assert final["mapping"]["opened_by"] == "other"
