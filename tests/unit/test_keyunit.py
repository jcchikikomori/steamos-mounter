"""The key dialog unit: state diagram, locks, deadline, save question, key-stop.

Design Doc "Key Dialog Unit" (state diagram, unlock and record, save, K2,
one at a time, unplug), "Locks" (no human wait under a volume lock), the
Data Contract ``keyunit.run`` and ADR-0005 D1, D4, D5. Real files, records
and ``flock`` under ``tmp_path``; logind, the user manager, the dialog
transport, cryptsetup and systemctl on the fake runner
(``tests/helpers/key_dialog.py``). Key checks compare booleans, so a failing
test never prints the key.
"""

import fcntl
import json
import logging
import os
import threading

import pytest

from steamos_mounter import keyunit, locks, reconcile
from steamos_mounter.journal import NOTICE
from steamos_mounter.model import InstanceKind, Trigger, VolumeState
from steamos_mounter.records import update_record
from steamos_mounter.sensitive import live_secrets
from steamos_mounter.teardown_report import ServiceResult
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import (
    CRYPTSETUP,
    LOGINCTL,
    MOUNT,
    PROBE,
    SETFACL,
    SYSTEMCTL,
    SYSTEMD_RUN,
    TABLE_ARGV,
    read_record,
    readback_argv,
    script_lsblk,
    sm_fields,
    write_key_file,
)
from tests.helpers.key_dialog import (
    DIALOG_LOCK,
    DIALOG_STOP,
    ENTERED,
    KEY_FILE,
    LEFTOVER_STOP,
    LOGGER,
    MAPPING_NAME,
    MEDIABOX_UUID,
    NO,
    PERSONAL_DEVICE_PATH,
    PERSONAL_RECORD,
    PERSONAL_UUID,
    RELOAD_REGISTERED,
    SESSION_ENV,
    SHOW_ENVIRONMENT,
    TEST_KEY,
    VOLUME_LOCK,
    YES,
    given_key_unit_started,
    is_notify,
    is_password,
    is_save,
    key_found_outside,
    script_key_unit_flow,
    script_reload,
    script_session,
)

PASSWORD_PROMPT = (
    "PERSONAL is locked. Its stored key did not work. Enter the BitLocker "
    "password or the 48-digit recovery key."
)
PASSWORD_ARGV = (
    SYSTEMD_RUN,
    "--user",
    "--pipe",
    "--wait",
    "--quiet",
    "--collect",
    f"--unit=steamos-mounter-dialog-{PERSONAL_UUID}",
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
OPEN_ARGV = (
    CRYPTSETUP,
    "open",
    "--type",
    "bitlk",
    "--key-file=-",
    "/dev/sdb1",
    MAPPING_NAME,
)
MEDIABOX_PATH = "/run/media/deck/MEDIABOX"
MEDIABOX_NTFS3_RW = Answer(
    stdout=json.dumps(
        {
            "filesystems": [
                {
                    "target": MEDIABOX_PATH,
                    "source": "/dev/sdb5",
                    "fstype": "ntfs3",
                    "vfs-options": "rw,nosuid,nodev,relatime",
                    "fs-options": "rw,uid=1000,gid=1000,windows_names",
                    "maj:min": "8:21",
                }
            ]
        }
    ).encode()
)
UDISKS_NAME = "PAT4T4SHUAWEI_PERSONAL_4_3_2024"


@pytest.fixture
def opened(ctx, tmp_path, host_tree):
    """PERSONAL waits for its key; the hook ``cryptsetup open`` runs on sysfs."""
    return given_key_unit_started(ctx, tmp_path, host_tree)


def run_key_unit(ctx) -> None:
    keyunit.run(ctx, PERSONAL_DEVICE_PATH)


def record(tmp_path) -> dict:
    return read_record(tmp_path, PERSONAL_RECORD)


def argvs_where(fake_runner, predicate) -> list[tuple[str, ...]]:
    return [call.argv for call in fake_runner.calls if predicate(call)]


def opens(fake_runner) -> list[tuple[str, ...]]:
    return [argv for argv in fake_runner.argvs if argv[0] == CRYPTSETUP]


def key_entries(caplog, volume_state: str) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if sm_fields(r).get("SM_EVENT") == "key"
        and sm_fields(r).get("SM_STATE") == volume_state
    ]


def held(ctx, take) -> bool:
    """True when ``take`` (a lock context manager factory) cannot get the lock now."""
    try:
        with take():
            return False
    except locks.LockTimeout:
        return True


def volume_lock_held(ctx) -> bool:
    return held(ctx, lambda: locks.volume_lock(ctx, PERSONAL_UUID, timeout=0))


def dialog_lock_held(ctx) -> bool:
    return held(ctx, lambda: locks.dialog_lock(ctx, timeout=0))


def no_key_left() -> bool:
    return all(TEST_KEY not in secret for secret in live_secrets())


def test_key_unit_deadline_is_270_seconds_inside_runtime_max_sec():
    assert keyunit.KEY_UNIT_DEADLINE == 270.0


# --- AC-070: the dialog in the Desktop Mode session ---------------------------------


def test_dialog_shown_in_desktop(ctx, fake_runner, tmp_path, opened):
    """AC-070, AC-076: session checked first, then the dialog; the record says so."""
    during = []
    script_session(fake_runner)
    fake_runner.on(
        is_password, Answer(), hook=lambda _cmd: during.append(record(tmp_path))
    )

    run_key_unit(ctx)

    [call] = [c for c in fake_runner.calls if c.argv[0] == SYSTEMD_RUN]
    assert call.argv == PASSWORD_ARGV
    assert (call.user, call.group, dict(call.env_extra)) == (1000, 1000, SESSION_ENV)
    assert call.secret_stdout
    assert (
        [argv[:2] for argv in fake_runner.argvs]
        == [
            (LOGINCTL, "show-user"),
            (LOGINCTL, "show-seat"),
            (LOGINCTL, "show-session"),
            SHOW_ENVIRONMENT[:2],
            LEFTOVER_STOP[:2],  # a leftover dialog unit is stopped first
            PASSWORD_ARGV[:2],
        ]
    )
    assert fake_runner.argvs[3] == SHOW_ENVIRONMENT
    assert fake_runner.argvs[4] == LEFTOVER_STOP
    [shown] = during
    assert (shown["state"], shown["reason"]) == ("NeedsKey", "dialog_open")
    assert shown["dialog"]["outcome"] == "shown"
    assert shown["next_step"] == "Answer the key dialog on the Deck's screen."


@pytest.mark.parametrize(
    ("reason", "key_file", "sentence"),
    [
        ("stored_key_missing", False, "It has no stored key."),
        ("stored_key_rejected", True, "Its stored key did not work."),
        (None, False, "It has no stored key."),
        (None, True, "Its stored key did not work."),
        ("no_session", False, "It has no stored key."),
    ],
)
def test_prompt_says_why_the_key_is_needed(
    ctx, fake_runner, tmp_path, host_tree, reason, key_file, sentence
):
    """The record's stored-key reason, else whether a key file exists."""
    given_key_unit_started(ctx, tmp_path, host_tree, reason=reason)
    if key_file:
        write_key_file(tmp_path, PERSONAL_UUID, b"old key")
    script_session(fake_runner)
    fake_runner.on(is_password, Answer())

    run_key_unit(ctx)

    [prompt] = [argv[-1] for argv in argvs_where(fake_runner, is_password)]
    assert prompt == (
        f"PERSONAL is locked. {sentence} Enter the BitLocker password or the"
        " 48-digit recovery key."
    )


@pytest.mark.parametrize(
    ("verdict", "show_user", "reason", "words"),
    [
        (
            "none",
            Answer(stdout=b"Display=\n"),
            "no_session",
            "there was no Desktop Mode session for the key dialog",
        ),
        (
            "not-sure",
            Answer(returncode=1),
            "session_not_sure",
            "the Desktop Mode session could not be confirmed for the key dialog",
        ),
    ],
)
def test_no_desktop_session_records_needs_key_and_shows_nothing(
    ctx, fake_runner, tmp_path, opened, caplog, verdict, show_user, reason, words
):
    """AC-075, AC-076: no dialog, no dialog lock, NeedsKey with the reason."""
    caplog.set_level(logging.DEBUG)
    fake_runner.on((LOGINCTL, "show-user"), show_user)

    run_key_unit(ctx)

    [query] = fake_runner.argvs  # one loginctl query, then nothing
    assert query[:2] == (LOGINCTL, "show-user")
    saved = record(tmp_path)
    assert (saved["state"], saved["reason"]) == ("NeedsKey", reason)
    assert saved["warning"] == f"The stored key did not work, and {words}."
    assert not (tmp_path / DIALOG_LOCK).exists()
    [entry] = key_entries(caplog, "NeedsKey")
    assert entry.levelno == logging.WARNING


def test_mapping_already_open_shows_no_dialog(
    ctx, fake_runner, tmp_path, host_tree, caplog
):
    """State diagram "mapping already open (Dolphin)": done, record untouched."""
    caplog.set_level(logging.DEBUG)
    opened = given_key_unit_started(ctx, tmp_path, host_tree)
    opened(None)  # the holder is back: Dolphin unlocked it before the unit ran
    before = record(tmp_path)
    script_session(fake_runner)

    run_key_unit(ctx)

    assert argvs_where(fake_runner, is_password) == []
    assert record(tmp_path) == before
    assert any("is unlocked already" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(
    "setup",
    ["unknown-uuid", "not-bitlocker", "registry-unusable", "device-gone", "odd-link"],
)
def test_nothing_runs_without_a_registered_present_bitlocker_volume(
    ctx, fake_runner, tmp_path, opened, caplog, setup
):
    caplog.set_level(logging.DEBUG)
    device_path = PERSONAL_DEVICE_PATH
    if setup == "unknown-uuid":
        device_path = "/dev/disk/by-uuid/0123456789ABCDEF"
    elif setup == "not-bitlocker":
        device_path = f"/dev/disk/by-uuid/{MEDIABOX_UUID}"
    elif setup == "registry-unusable":
        (tmp_path / "etc/steamos-mounter/config.toml").write_text("[[volume", "utf-8")
    else:
        link = tmp_path / PERSONAL_DEVICE_PATH.lstrip("/")
        link.unlink()
        if setup == "odd-link":  # resolves outside /dev: not a partition
            link.symlink_to(tmp_path / "elsewhere" / "sdb1")

    keyunit.run(ctx, device_path)

    assert fake_runner.calls == []
    expected = NOTICE if setup in {"device-gone", "odd-link"} else logging.ERROR
    assert [r.levelno for r in caplog.records if r.name == LOGGER] == [expected]


# --- AC-071: the entered key unlocks, the reload mounts -----------------------------


def test_entered_key_mounts_via_reload(ctx, fake_runner, tmp_path, opened):
    """AC-071, J001: open on stdin under the volume lock, record, then reload."""
    ahead, at_reload, lock_during_open, lock_at_reload = [], [], [], []

    def reload_requested(_command) -> None:
        at_reload.append(record(tmp_path))
        lock_at_reload.append(volume_lock_held(ctx))

    def cryptsetup_opens(command) -> None:
        ahead.append(record(tmp_path)["mapping"])
        lock_during_open.append(volume_lock_held(ctx))
        opened(command)

    script_key_unit_flow(
        fake_runner,
        cryptsetup_opens,
        hooks={"reload": reload_requested},
    )

    run_key_unit(ctx)

    [open_call] = [c for c in fake_runner.calls if c.argv[0] == CRYPTSETUP]
    assert open_call.argv == OPEN_ARGV
    assert open_call.secret_stdin
    stdin_is_key = open_call.stdin == TEST_KEY
    assert stdin_is_key  # one trailing newline stripped, once
    assert lock_during_open == [True]
    assert lock_at_reload == [False]  # the reload is asked for after the release
    assert [(m["name"], m["opened_by"], m["save_pending"]) for m in ahead] == [
        (MAPPING_NAME, "key-unit", False)  # DD-10: the name is on disk first
    ]
    [then] = at_reload
    assert (then["state"], then["dialog"]["outcome"]) == ("Mounting", "unlocked")
    assert then["mapping"] == {
        "name": MAPPING_NAME,
        "kname": None,
        "devnum": None,
        "opened_by": "key-unit",
        "key_unit_invocation_id": ctx.invocation_id,
        "save_pending": True,
    }
    assert RELOAD_REGISTERED in fake_runner.argvs
    assert no_key_left()


def test_yes_saves_the_key_and_clears_save_pending(ctx, fake_runner, tmp_path, opened):
    """AC-072: Yes stores exactly the opening bytes, 0600; no second key test."""
    script_key_unit_flow(fake_runner, opened, save=YES)

    run_key_unit(ctx)

    key_file = tmp_path / KEY_FILE
    stored = key_file.read_bytes() == TEST_KEY
    assert stored
    assert key_file.stat().st_mode & 0o777 == 0o600
    assert key_file.parent.stat().st_mode & 0o777 == 0o700
    assert len(opens(fake_runner)) == 1  # the open was the FR-16 test
    saved = record(tmp_path)
    assert (saved["mapping"]["save_pending"], saved["dialog"]["outcome"]) == (
        False,
        "saved",
    )
    save_index = fake_runner.argvs.index(argvs_where(fake_runner, is_save)[0])
    reload_index = fake_runner.argvs.index(RELOAD_REGISTERED)
    # The second session check runs between the reload request and the question.
    between = fake_runner.argvs[reload_index + 1 : save_index]
    assert [argv[:2] for argv in between] == [
        (LOGINCTL, "show-user"),
        (LOGINCTL, "show-seat"),
        (LOGINCTL, "show-session"),
        SHOW_ENVIRONMENT[:2],
        LEFTOVER_STOP[:2],
    ]
    assert no_key_left()


def test_typed_key_keeps_its_trailing_spaces(ctx, fake_runner, tmp_path, opened):
    """Only the dialog's one newline goes (dialog.py): no second strip here."""
    spaced = TEST_KEY + b"  "
    script_key_unit_flow(
        fake_runner, opened, password=Answer(stdout=spaced + b"\n"), save=YES
    )

    run_key_unit(ctx)

    [open_call] = [c for c in fake_runner.calls if c.argv[0] == CRYPTSETUP]
    stdin_is_spaced = open_call.stdin == spaced
    stored_is_spaced = (tmp_path / KEY_FILE).read_bytes() == spaced
    assert stdin_is_spaced
    assert stored_is_spaced
    assert no_key_left()


@pytest.mark.parametrize("answer", ["no", "close", "timeout", "unplug", "mode-switch"])
def test_save_only_on_yes(
    ctx, fake_runner, tmp_path, opened, fake_clock, caplog, answer
):
    """AC-072, AC-078: anything but Yes stores nothing; save_pending is cleared."""
    caplog.set_level(logging.DEBUG)

    def unplugged(_command) -> None:
        raise SystemExit(0)  # SIGTERM from BindsTo=, as unit_entry turns it

    save = {
        "no": NO,
        "close": Answer(returncode=2),
        "timeout": Answer.timeout(),
        "unplug": NO,
        "mode-switch": YES,
    }[answer]
    if answer == "mode-switch":
        fake_runner.on((LOGINCTL, "show-user"), "loginctl-user-deck.txt")
        fake_runner.on((LOGINCTL, "show-user"), Answer(stdout=b"Display=\n"))
    hooks = {"save": unplugged} if answer == "unplug" else None
    script_key_unit_flow(fake_runner, opened, save=save, hooks=hooks)

    if answer == "unplug":
        with pytest.raises(SystemExit):
            run_key_unit(ctx)
    else:
        run_key_unit(ctx)

    assert not (tmp_path / KEY_FILE).exists()
    saved = record(tmp_path)
    assert (saved["mapping"]["save_pending"], saved["dialog"]["outcome"]) == (
        False,
        "not-saved",
    )
    asked = len(argvs_where(fake_runner, is_save))
    assert asked == (0 if answer == "mode-switch" else 1)
    if answer == "timeout":
        assert DIALOG_STOP in fake_runner.argvs  # dialog.stop after the 60 s timer
    assert no_key_left()
    assert not volume_lock_held(ctx)
    assert not dialog_lock_held(ctx)
    [entry] = [r for r in caplog.records if r.getMessage() == "PERSONAL: key not saved"]
    assert entry.levelno == NOTICE


def test_save_outcome_recorded_when_the_mapping_is_gone_from_the_record(
    ctx, fake_runner, tmp_path, opened
):
    """A teardown dropped the mapping meanwhile: the outcome is still recorded."""

    def torn_down(_command) -> None:
        update_record(
            ctx,
            InstanceKind.REGISTERED,
            PERSONAL_UUID,
            lambda saved: setattr(saved, "mapping", None),
        )

    script_key_unit_flow(fake_runner, opened, hooks={"save": torn_down})

    run_key_unit(ctx)

    saved = record(tmp_path)
    assert (saved["mapping"], saved["dialog"]["outcome"]) == (None, "not-saved")


def test_no_save_question_without_time_left(
    ctx, fake_runner, tmp_path, opened, fake_clock
):
    """A save question that would outlive the 270 s deadline is not asked."""

    def slow_open(command) -> None:
        fake_clock.advance(keyunit.KEY_UNIT_DEADLINE - 55)
        opened(command)

    script_key_unit_flow(fake_runner, slow_open, save=YES)

    run_key_unit(ctx)

    assert argvs_where(fake_runner, is_save) == []
    assert record(tmp_path)["dialog"]["outcome"] == "not-saved"
    assert not (tmp_path / KEY_FILE).exists()


def test_mount_request_failure_still_asks_to_save(
    ctx, fake_runner, tmp_path, opened, caplog
):
    caplog.set_level(logging.DEBUG)
    script_session(fake_runner)
    fake_runner.on(is_password, ENTERED)
    fake_runner.on(CRYPTSETUP, Answer(), hook=opened)
    fake_runner.on((SYSTEMCTL, "show"), Answer(returncode=1, stderr=b"bus error"))
    fake_runner.on(is_save, YES)

    run_key_unit(ctx)

    assert (tmp_path / KEY_FILE).exists()
    warned = [r for r in caplog.records if "could not be requested" in r.getMessage()]
    assert [r.levelno for r in warned] == [logging.WARNING]


def test_untrusted_key_store_records_not_saved(
    ctx, fake_runner, tmp_path, opened, caplog
):
    caplog.set_level(logging.DEBUG)
    (tmp_path / KEY_FILE).parent.chmod(0o755)
    script_key_unit_flow(fake_runner, opened, save=YES)

    run_key_unit(ctx)

    assert not (tmp_path / KEY_FILE).exists()
    assert record(tmp_path)["dialog"]["outcome"] == "not-saved"
    errors = [r for r in caplog.records if "was not saved" in r.getMessage()]
    assert [r.levelno for r in errors] == [logging.ERROR]
    assert no_key_left()


def test_unrecorded_save_outcome_is_logged(
    ctx, fake_runner, tmp_path, opened, fake_clock, caplog
):
    """No time left for the volume lock after the question: an ERROR, no raise."""
    caplog.set_level(logging.DEBUG)

    fd = os.open(tmp_path / VOLUME_LOCK, os.O_RDWR | os.O_CREAT, 0o600)

    def answered_late(_command) -> None:
        fake_clock.advance(keyunit.KEY_UNIT_DEADLINE)
        lock_fd(fd)  # reconcile holds the volume lock as the time runs out

    script_key_unit_flow(fake_runner, opened, hooks={"save": answered_late})
    try:
        run_key_unit(ctx)
    finally:
        os.close(fd)

    assert record(tmp_path)["mapping"]["save_pending"] is True
    errors = [r for r in caplog.records if "was not recorded" in r.getMessage()]
    assert [r.levelno for r in errors] == [logging.ERROR]


def lock_fd(fd: int) -> None:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


# --- AC-073 and K2: cancel, timeout, dialog failure, wrong key ----------------------


def test_cancel_records_cancelled(ctx, fake_runner, tmp_path, opened, caplog):
    """AC-073: empty output is a cancel; nothing opened, stored or notified."""
    caplog.set_level(logging.DEBUG)
    script_key_unit_flow(fake_runner, opened, password=Answer())

    run_key_unit(ctx)

    saved = record(tmp_path)
    assert (saved["state"], saved["reason"], saved["mapping"]) == (
        "UnlockCancelled",
        "dialog_cancelled",
        None,
    )
    assert saved["dialog"]["outcome"] == "cancelled"
    assert opens(fake_runner) == []
    assert argvs_where(fake_runner, is_notify) == []
    assert not (tmp_path / KEY_FILE).exists()
    [entry] = key_entries(caplog, "UnlockCancelled")
    assert entry.levelno == logging.WARNING


@pytest.mark.parametrize(
    ("password", "state", "reason", "outcome", "notified"),
    [
        (Answer.timeout(), "UnlockCancelled", "dialog_timed_out", "timed-out", 0),
        (Answer(returncode=134), "NeedsKey", "dialog_failed", "failed", 1),
    ],
    ids=["timed-out", "dialog-failed"],
)
def test_timeout_and_dialog_failure(
    ctx, fake_runner, tmp_path, opened, password, state, reason, outcome, notified
):
    """Outcome mapping; K2: a failed dialog is NeedsKey dialog_failed, notified."""
    script_key_unit_flow(fake_runner, opened, password=password)

    run_key_unit(ctx)

    saved = record(tmp_path)
    assert (saved["state"], saved["reason"], saved["dialog"]["outcome"]) == (
        state,
        reason,
        outcome,
    )
    notices = argvs_where(fake_runner, is_notify)
    assert len(notices) == notified
    if notified:
        assert notices[0][-2:] == (
            "PERSONAL needs a key",
            "The key dialog could not be shown. Run sudo /opt/steamos-mounter/bin/"
            "steamos-mounter set-key PERSONAL, or unlock it in Dolphin.",
        )
    assert opens(fake_runner) == []


def test_wrong_key_records_failed(ctx, fake_runner, tmp_path, opened, caplog):
    """AC-073: one attempt, UnlockFailed, the DD-19 notification, nothing saved."""
    caplog.set_level(logging.DEBUG)
    script_key_unit_flow(fake_runner, opened, open_rc=2)

    run_key_unit(ctx)

    assert len(opens(fake_runner)) == 1
    saved = record(tmp_path)
    assert (saved["state"], saved["reason"], saved["mapping"]) == (
        "UnlockFailed",
        None,
        None,
    )
    assert saved["dialog"]["outcome"] == "unlock-failed"
    [notice] = argvs_where(fake_runner, is_notify)
    assert notice[-2] == "PERSONAL did not unlock"
    assert RELOAD_REGISTERED not in fake_runner.argvs
    assert argvs_where(fake_runner, is_save) == []
    assert not (tmp_path / KEY_FILE).exists()
    [entry] = key_entries(caplog, "UnlockFailed")
    assert entry.levelno == logging.ERROR
    assert no_key_left()
    assert not key_found_outside(fake_runner, caplog, tmp_path)


def test_cryptsetup_failure_records_mount_failed(ctx, fake_runner, tmp_path, opened):
    script_key_unit_flow(fake_runner, opened, open_rc=1)

    run_key_unit(ctx)

    saved = record(tmp_path)
    assert (saved["state"], saved["reason"], saved["mapping"]) == (
        "MountFailed",
        "unknown",
        None,
    )
    assert saved["warning"] == (
        "PERSONAL could not be unlocked with the typed key: cryptsetup failed."
    )
    [notice] = argvs_where(fake_runner, is_notify)
    assert notice[-2] == "PERSONAL could not be mounted"


def test_failed_open_beside_a_new_mapping_is_left_to_reconcile(
    ctx, fake_runner, tmp_path, host_tree, caplog
):
    """cryptsetup failed because Dolphin opened it meanwhile: no failure recorded."""
    caplog.set_level(logging.DEBUG)
    opened = given_key_unit_started(ctx, tmp_path, host_tree)
    script_key_unit_flow(fake_runner, opened, open_rc=5, hooks={"open": opened})

    run_key_unit(ctx)

    saved = record(tmp_path)
    assert (saved["state"], saved["reason"], saved["mapping"]) == (
        "NeedsKey",
        "dialog_open",
        None,
    )
    assert argvs_where(fake_runner, is_notify) == []
    assert any("unlocked another way" in r.getMessage() for r in caplog.records)


def test_mapping_opened_while_the_dialog_was_open_is_not_opened_again(
    ctx, fake_runner, tmp_path, opened, caplog
):
    caplog.set_level(logging.DEBUG)
    script_key_unit_flow(fake_runner, opened, hooks={"password": opened})

    run_key_unit(ctx)

    assert opens(fake_runner) == []
    assert RELOAD_REGISTERED not in fake_runner.argvs
    assert any("unlocked another way" in r.getMessage() for r in caplog.records)
    assert no_key_left()


def test_notification_needs_a_desktop_session(
    ctx, fake_runner, tmp_path, opened, caplog
):
    """DD-19: the K2 notification only after the logind half says Desktop Mode."""
    caplog.set_level(logging.DEBUG)
    fake_runner.on((LOGINCTL, "show-user"), "loginctl-user-deck.txt")
    fake_runner.on((LOGINCTL, "show-user"), Answer(stdout=b"Display=\n"))
    script_key_unit_flow(fake_runner, opened, password=Answer(returncode=134))

    run_key_unit(ctx)

    assert argvs_where(fake_runner, is_notify) == []
    assert any("is not notified" in r.getMessage() for r in caplog.records)


def test_notification_skipped_without_time_left(
    ctx, fake_runner, tmp_path, opened, fake_clock, caplog
):
    caplog.set_level(logging.DEBUG)

    def failed_late(_command) -> None:
        fake_clock.advance(keyunit.KEY_UNIT_DEADLINE + 1)

    script_session(fake_runner)
    fake_runner.on(is_password, Answer(returncode=134), hook=failed_late)

    run_key_unit(ctx)

    assert argvs_where(fake_runner, is_notify) == []
    assert record(tmp_path)["reason"] == "dialog_failed"
    assert any("no time left" in r.getMessage() for r in caplog.records)


# --- AC-078, NFR-02: locks while a question is open; unplug -------------------------


def test_no_volume_lock_while_dialog_open(ctx, fake_runner, tmp_path, opened):
    """NFR-02: with a question open only the dialog lock is held; MEDIABOX mounts."""
    seen, mounted = [], []

    def other_drive_mounts(_command) -> None:
        seen.append(volume_lock_held(ctx))
        outcome = reconcile.run(
            ctx,
            InstanceKind.REGISTERED,
            f"/dev/disk/by-uuid/{MEDIABOX_UUID}",
            Trigger.START,
        )
        mounted.append(outcome.state)

    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    fake_runner.on(TABLE_ARGV, "findmnt-real-list.json", repeat=True)
    fake_runner.on(SETFACL, Answer(), repeat=True)
    fake_runner.on(PROBE, Answer())
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback_argv(MEDIABOX_PATH), MEDIABOX_NTFS3_RW)
    script_session(fake_runner)
    fake_runner.on(is_password, ENTERED, hook=other_drive_mounts)
    fake_runner.on(CRYPTSETUP, Answer(), hook=opened)
    script_reload(fake_runner)
    fake_runner.on(is_save, NO, hook=lambda _c: seen.append(volume_lock_held(ctx)))

    run_key_unit(ctx)

    assert seen == [False, False]  # neither question ran under the volume lock
    assert mounted == [VolumeState.MOUNTED_RW]
    [mount] = [argv for argv in fake_runner.argvs if argv[0] == MOUNT]
    assert mount[-1] == MEDIABOX_PATH


def test_dialog_lock_held_across_both_questions(ctx, fake_runner, tmp_path, opened):
    """One dialog at a time: held from the password dialog to the save answer."""
    seen = []

    def check(_command) -> None:
        seen.append(dialog_lock_held(ctx))

    script_session(fake_runner)
    fake_runner.on(is_password, ENTERED, hook=check)
    fake_runner.on(CRYPTSETUP, Answer(), hook=opened)
    script_reload(fake_runner)
    fake_runner.on(is_save, NO, hook=check)

    run_key_unit(ctx)

    assert seen == [True, True]
    assert not dialog_lock_held(ctx)


def test_leftover_unit_stopped_before_each_question(ctx, fake_runner, tmp_path, opened):
    script_key_unit_flow(fake_runner, opened)

    run_key_unit(ctx)

    argvs = fake_runner.argvs
    for question in (is_password, is_save):
        [argv] = argvs_where(fake_runner, question)
        assert argvs[argvs.index(argv) - 1] == LEFTOVER_STOP


def test_second_dialog_waits_for_the_dialog_lock(ctx, fake_runner, tmp_path, opened):
    """One at a time: the unit waits while another dialog holds the lock."""
    released = threading.Event()
    releaser = hold_dialog_lock_until_released(tmp_path, released)
    seen = []
    script_key_unit_flow(
        fake_runner,
        opened,
        password=Answer(),
        hooks={"password": lambda _c: seen.append(released.is_set())},
    )

    releaser.start()
    try:
        run_key_unit(ctx)
    finally:
        releaser.join(5)

    assert seen == [True]  # the dialog came only after the other one let go


def hold_dialog_lock_until_released(tmp_path, released) -> threading.Timer:
    """Another key unit's dialog: the lock is held now and let go after 0.3 s."""
    fd = os.open(tmp_path / DIALOG_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    lock_fd(fd)

    def release() -> None:
        released.set()
        os.close(fd)

    return threading.Timer(0.3, release)


@pytest.mark.parametrize(
    ("logind_seconds", "shown"),
    [(136, False), (134, True)],
    ids=["134s-left", "136s-left"],
)
def test_dialog_lock_wait_ends_while_the_dialog_still_fits_the_deadline(
    ctx, fake_runner, tmp_path, opened, fake_clock, logind_seconds, shown
):
    """The 270 s deadline: the lock is waited for only while 120 s of dialog plus
    15 s of leftover stop still fit; 134 s left gives up, 136 s left waits."""
    released = threading.Event()
    releaser = hold_dialog_lock_until_released(tmp_path, released)
    seen = []

    def slow_logind(_command) -> None:
        fake_clock.advance(logind_seconds)

    fake_runner.on((LOGINCTL, "show-user"), "loginctl-user-deck.txt", hook=slow_logind)
    script_session(fake_runner)
    fake_runner.on(
        is_password, Answer(), hook=lambda _c: seen.append(released.is_set())
    )

    releaser.start()
    try:
        run_key_unit(ctx)
    finally:
        releaser.join(5)

    saved = record(tmp_path)
    if shown:
        assert seen == [True]
        assert (saved["state"], saved["reason"]) == (
            "UnlockCancelled",
            "dialog_cancelled",
        )
    else:
        assert seen == []
        assert (saved["state"], saved["reason"]) == ("NeedsKey", "stored_key_rejected")
        assert saved["warning"] == (
            "The stored key did not work, and another key dialog was open until no"
            " time was left for this one."
        )


def test_session_check_runs_within_the_deadline(ctx, fake_runner, opened, fake_clock):
    def slow_logind(_command) -> None:
        fake_clock.advance(keyunit.KEY_UNIT_DEADLINE - 4)

    fake_runner.on((LOGINCTL, "show-user"), "loginctl-user-deck.txt", hook=slow_logind)
    script_session(fake_runner)
    fake_runner.on(is_password, Answer())

    run_key_unit(ctx)

    timeouts = [c.timeout for c in fake_runner.calls if c.argv[0] == LOGINCTL]
    assert timeouts == [10.0, 4.0, 4.0]


def test_unplug_stops_dialog_nothing_stored(ctx, fake_runner, tmp_path, opened):
    """AC-078: SIGTERM while the dialog is open, then key-stop closes the dialog."""

    def unplugged(_command) -> None:
        raise SystemExit(0)

    script_session(fake_runner)
    fake_runner.on(is_password, ENTERED, hook=unplugged)

    with pytest.raises(SystemExit):
        run_key_unit(ctx)
    keyunit.stop_post(ctx, PERSONAL_DEVICE_PATH, ServiceResult("success", None, None))

    [stop] = [c for c in fake_runner.calls if c.argv == DIALOG_STOP]
    assert (stop.user, stop.group, dict(stop.env_extra)) == (1000, 1000, SESSION_ENV)
    assert opens(fake_runner) == []
    assert not (tmp_path / KEY_FILE).exists()
    assert not dialog_lock_held(ctx)
    # No key exists yet here: SIGTERM came before the dialog answered. The
    # next test covers SIGTERM while the key is live.


def test_sigterm_while_the_key_is_live_clears_it_and_both_locks(
    ctx, fake_runner, tmp_path, opened
):
    """SystemExit during cryptsetup open: the key is cleared, the locks are free."""

    def stopped(_command) -> None:
        raise SystemExit(0)

    script_key_unit_flow(fake_runner, opened, hooks={"open": stopped})

    with pytest.raises(SystemExit):
        run_key_unit(ctx)

    [open_call] = [c for c in fake_runner.calls if c.argv[0] == CRYPTSETUP]
    key_was_live = open_call.stdin == TEST_KEY
    assert key_was_live
    assert no_key_left()
    assert not volume_lock_held(ctx)
    assert not dialog_lock_held(ctx)
    assert not (tmp_path / KEY_FILE).exists()


@pytest.mark.parametrize(
    ("result", "level"),
    [("success", NOTICE), ("timeout", logging.ERROR)],
)
def test_stop_post_logs_the_service_result(ctx, fake_runner, caplog, result, level):
    caplog.set_level(logging.DEBUG)
    fake_runner.on(DIALOG_STOP, Answer())

    keyunit.stop_post(ctx, PERSONAL_DEVICE_PATH, ServiceResult(result, "exited", "0"))

    [entry] = [r for r in caplog.records if r.name == LOGGER]
    assert entry.levelno == level
    assert sm_fields(entry)["SM_REASON"] == result
    assert sm_fields(entry)["SM_EVENT"] == "key"
    assert fake_runner.argvs == [DIALOG_STOP]
