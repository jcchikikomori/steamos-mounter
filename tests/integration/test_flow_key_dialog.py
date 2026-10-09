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

from pathlib import Path

import pytest

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
    pytest.skip("skeleton: implement in Phase 4 (keyunit, dialog, session)")


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
        dialog" or "unlock failed" and a next step naming mount --volume
        PERSONAL or set-key PERSONAL (AC-040, AC-073)
      - caplog: one NOTICE or WARNING per case with SM_EVENT=key and the
        outcome; TEST_KEY absent from caplog, records and the FakeRunner log
    """
    pytest.skip("skeleton: implement in Phase 4 (keyunit, dialog, session)")


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
        (B observes mapping.opened_by already set; assert through timestamps
        from FakeClock or the FakeRunner call order: B's lsblk after A's
        cryptsetup)
      - exactly one mount of /dev/dm-0 at PERSONAL_PATH across both threads
        (AC-035); the volume lock is free at the end
      - "key-unit": no "systemctl stop" of KEY_UNIT in the log
      - "foreign": exactly one "systemctl stop --no-block <KEY_UNIT>" call
        (closes the dialog after a Dolphin unlock, ADR-0005 D5.2)
      - the test finishes within 5 s of FakeClock time and 10 s of wall time
        (no deadlock; join both threads with a timeout and fail if alive)
    """
    pytest.skip("skeleton: implement in Phase 4 (keyunit, dialog, session)")
