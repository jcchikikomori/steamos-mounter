"""Desktop notifications: which outcomes get one, their text, and the transport.

Design Doc "Notifications", DD-19, AC-046, AC-047 and ADR-0005 D3 item 8.
``notice_for`` is pure: it reads a ``VolumeView`` and the event that produced
it. ``send`` runs ``notify-send`` in the ``deck`` user manager through
``systemd-run --user`` as uid 1000; its flags are checked against the Deck's
``notify-send-help.txt`` and ``systemd-run-help.txt`` captures. Gating on
``session.check`` is the caller's job, so it is not exercised here.
"""

import logging
import re

import pytest

from steamos_mounter import state
from steamos_mounter.errors import SecretHandlingError
from steamos_mounter.model import InstanceKind, VolumeState
from steamos_mounter.notify import Notice, notice_for, out_of_time, send
from steamos_mounter.sensitive import SecretBytes
from steamos_mounter.state import VolumeView
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture

SYSTEMD_RUN = "/usr/bin/systemd-run"
NOTIFY_SEND = "/usr/bin/notify-send"
CLI = "sudo /opt/steamos-mounter/bin/steamos-mounter"
LOGGER = "steamos_mounter.notify"
DIRTY_WARNING = (
    "MEDIABOX is dirty: Windows did not close it cleanly. It is mounted"
    " read-write with ntfs-3g."
)
FALLBACK_WARNING = "ntfs3 refused the mount (exit 32); ntfs-3g mounted it."
SESSION_ENV = {
    "XDG_RUNTIME_DIR": "/run/user/1000",
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
}
MEDIABOX_NOTICE = Notice(
    summary="MEDIABOX is dirty",
    body=(
        "Mounted read-write with ntfs-3g at /run/media/deck/MEDIABOX."
        " Run chkdsk /f on it in Windows."
    ),
    urgency="normal",
)


def view(
    volume_state: VolumeState,
    *,
    name: str = "MEDIABOX",
    path: str | None = None,
    driver: str | None = None,
    mode: str | None = None,
    reason: str | None = None,
    warning: str | None = None,
    kind: InstanceKind = InstanceKind.REGISTERED,
) -> VolumeView:
    """A view as ``state.compute_views`` builds it, next step included."""
    return VolumeView(
        name=name,
        uuid="01D95F1575592A30",
        kind=kind,
        present=True,
        path=f"/run/media/deck/{name}" if path is None else path,
        driver=driver,
        mode=mode,
        state=volume_state,
        reason=reason,
        warning=warning,
        next_step=state.next_step(volume_state, reason, name=name, cli_root=CLI),
    )


# --- notice_for: the DD-19 list (AC-046) -------------------------------------------

NOTICE_CASES = [
    pytest.param(
        view(
            VolumeState.MOUNTED_RW_DIRTY,
            driver="ntfs-3g",
            mode="rw",
            reason="dirty",
            warning=DIRTY_WARNING,
        ),
        MEDIABOX_NOTICE,
        id="dirty-mediabox-design-doc-example",
    ),
    pytest.param(
        view(
            VolumeState.MOUNTED_RO,
            name="MOVIES",
            driver="ntfs3",
            mode="ro",
            reason="unsafe",
        ),
        Notice(
            summary="MOVIES is read-only",
            body=(
                "Mounted read-only at /run/media/deck/MOVIES because it is in an"
                " unsafe state (hibernation, Fast Startup, or an abrupt unplug)."
                " Shut Windows down fully (no Fast Startup), then run chkdsk /f on"
                " it in Windows."
            ),
            urgency="normal",
        ),
        id="read-only-unsafe",
    ),
    pytest.param(
        view(VolumeState.MOUNTED_RO, name="MOVIES", driver="ntfs-3g", mode="ro"),
        Notice(
            summary="MOVIES is read-only",
            body=(
                "Mounted read-only at /run/media/deck/MOVIES."
                " See journalctl -t steamos-mounter SM_VOLUME=MOVIES."
            ),
            urgency="normal",
        ),
        id="read-only-other",
    ),
    pytest.param(
        view(
            VolumeState.MOUNTED_RW,
            name="MOVIES",
            driver="ntfs-3g",
            mode="rw",
            warning=FALLBACK_WARNING,
        ),
        Notice(
            summary="MOVIES is mounted with ntfs-3g",
            body=(
                "Mounted read-write with ntfs-3g at /run/media/deck/MOVIES."
                " ntfs3 refused the mount (exit 32); ntfs-3g mounted it."
            ),
            urgency="normal",
        ),
        id="ntfs-3g-with-warning",
    ),
    pytest.param(
        view(VolumeState.MOUNT_FAILED, name="GAMES", reason="device_busy"),
        Notice(
            summary="GAMES could not be mounted",
            body=(
                f"Mount failed: device busy. Wait, then run {CLI} mount --volume GAMES."
            ),
            urgency="critical",
        ),
        id="mount-failed",
    ),
    pytest.param(
        view(VolumeState.MOUNT_FAILED, name="GAMES", reason="unknown"),
        Notice(
            summary="GAMES could not be mounted",
            body=f"Mount failed. See the journal, then run {CLI} mount --volume GAMES.",
            urgency="critical",
        ),
        id="mount-failed-unknown",
    ),
    pytest.param(
        view(VolumeState.MOUNT_TIMED_OUT, name="GAMES"),
        Notice(
            summary="GAMES could not be mounted",
            body=f"Mount timed out. Run {CLI} mount --volume GAMES to try again.",
            urgency="critical",
        ),
        id="mount-timed-out",
    ),
    pytest.param(
        view(VolumeState.UNLOCK_FAILED, name="PERSONAL"),
        Notice(
            summary="PERSONAL did not unlock",
            body=(
                "The key was rejected. Replug the drive or run"
                f" {CLI} mount --volume PERSONAL to try again, or run"
                f" {CLI} set-key PERSONAL."
            ),
            urgency="critical",
        ),
        id="unlock-failed",
    ),
    pytest.param(
        view(VolumeState.NEEDS_KEY, name="PERSONAL", reason="key_permissions"),
        Notice(
            summary="PERSONAL needs a key",
            body=(
                "The stored key file has unsafe permissions or an unexpected owner."
                f" Run {CLI} doctor, then {CLI} set-key PERSONAL."
            ),
            urgency="critical",
        ),
        id="needs-key-permissions",
    ),
    pytest.param(
        view(VolumeState.NEEDS_KEY, name="PERSONAL", reason="dialog_failed"),
        Notice(
            summary="PERSONAL needs a key",
            body=(
                "The key dialog could not be shown."
                f" Run {CLI} set-key PERSONAL, or unlock it in Dolphin."
            ),
            urgency="critical",
        ),
        id="needs-key-dialog-failed",
    ),
]


@pytest.mark.parametrize(("volume_view", "expected"), NOTICE_CASES)
def test_notice_texts(volume_view, expected):
    assert notice_for(volume_view, event="reconcile") == expected


def test_notice_texts_match_the_design_doc_example():
    mediabox = view(
        VolumeState.MOUNTED_RW_DIRTY,
        driver="ntfs-3g",
        mode="rw",
        reason="dirty",
        warning=DIRTY_WARNING,
    )

    notice = notice_for(mediabox, event="reconcile")

    assert notice is not None
    assert notice.summary == "MEDIABOX is dirty"
    assert notice.body == (
        "Mounted read-write with ntfs-3g at /run/media/deck/MEDIABOX."
        " Run chkdsk /f on it in Windows."
    )


@pytest.mark.parametrize(
    "volume_view",
    [
        view(VolumeState.UNLOCK_FAILED, name="PERSONAL"),
        view(VolumeState.NEEDS_KEY, name="PERSONAL", reason="dialog_failed"),
    ],
)
def test_key_unit_outcomes_notify_too(volume_view):
    # K2 and the rejected typed key come from the key unit (event "key").
    assert notice_for(volume_view, event="key") is not None


# --- notice_for: never ---------------------------------------------------------------


@pytest.mark.parametrize(
    "reason", ["stored_key_missing", "stored_key_rejected", "dialog_open"]
)
def test_no_notice_when_key_unit_started(reason):
    # The registered instance started the key unit; its dialog replaces AC-014's
    # notification (AC-014, AC-046, ADR-0005 D1 item 4).
    needs_key = view(VolumeState.NEEDS_KEY, name="PERSONAL", reason=reason)

    assert notice_for(needs_key, event="reconcile") is None
    assert notice_for(needs_key, event="key") is None


@pytest.mark.parametrize(
    "volume_view",
    [
        pytest.param(
            view(VolumeState.NEEDS_KEY, name="PERSONAL", reason="no_session"),
            id="needs-key-no-session",
        ),
        pytest.param(
            view(VolumeState.NEEDS_KEY, name="PERSONAL", reason="session_not_sure"),
            id="needs-key-not-sure",
        ),
        pytest.param(view(VolumeState.NEEDS_KEY, name="PERSONAL"), id="needs-key"),
        pytest.param(
            view(
                VolumeState.UNLOCK_CANCELLED, name="PERSONAL", reason="dialog_cancelled"
            ),
            id="cancelled",
        ),
        pytest.param(
            view(
                VolumeState.UNLOCK_CANCELLED, name="PERSONAL", reason="dialog_timed_out"
            ),
            id="cancelled-timed-out",
        ),
        pytest.param(
            view(
                VolumeState.MOUNTED_ELSEWHERE,
                path="/run/media/deck/OTHER",
                driver="ntfs3",
                mode="rw",
            ),
            id="elsewhere",
        ),
        pytest.param(
            view(VolumeState.MOUNTED_ELSEWHERE, reason="held"), id="elsewhere-held"
        ),
        pytest.param(view(VolumeState.LOCKED, name="PERSONAL"), id="locked"),
        pytest.param(
            view(VolumeState.MOUNTED_RW, driver="ntfs3", mode="rw"), id="healthy-ntfs3"
        ),
        pytest.param(
            view(VolumeState.MOUNTED_RW, driver="ntfs-3g", mode="rw"),
            id="ntfs-3g-without-warning",
        ),
        pytest.param(
            view(
                VolumeState.MOUNTED_RW,
                driver="ntfs3",
                mode="rw",
                warning=FALLBACK_WARNING,
            ),
            id="warning-not-via-ntfs-3g",
        ),
        pytest.param(
            view(
                VolumeState.MOUNTED_RW,
                name="GAMES",
                driver="exfat",
                mode="rw",
                kind=InstanceKind.AUTO,
            ),
            id="healthy-auto",
        ),
        pytest.param(view(VolumeState.NOT_PRESENT), id="not-present"),
        pytest.param(view(VolumeState.NOT_MOUNTED), id="not-mounted"),
        pytest.param(view(VolumeState.MOUNTING), id="mounting"),
        pytest.param(view(VolumeState.UNMOUNTED_BY_USER), id="unmounted-by-user"),
    ],
)
def test_no_notice_for_other_states(volume_view):
    assert notice_for(volume_view, event="reconcile") is None
    assert notice_for(volume_view, event="key") is None


@pytest.mark.parametrize("event", ["teardown", "sweep", "list", "mount", ""])
def test_no_notice_outside_reconcile_and_key_outcomes(event):
    mediabox = view(
        VolumeState.MOUNTED_RW_DIRTY, driver="ntfs-3g", mode="rw", reason="dirty"
    )

    assert notice_for(mediabox, event=event) is None


# --- notice_for: markup cannot be injected -----------------------------------------


@pytest.mark.parametrize(("volume_view", "expected"), NOTICE_CASES)
def test_notice_texts_hold_no_markup_characters(volume_view, expected):
    hostile = VolumeView(
        name="A<b>&c",
        uuid=volume_view.uuid,
        kind=volume_view.kind,
        present=True,
        path="/run/media/deck/A<b>&c",
        driver=volume_view.driver,
        mode=volume_view.mode,
        state=volume_view.state,
        reason=volume_view.reason,
        warning="<i>x</i> & y" if volume_view.warning else None,
        next_step=volume_view.next_step + " <a href='x'>&amp;</a>",
    )

    notice = notice_for(hostile, event="reconcile")

    assert notice is not None
    assert notice.urgency == expected.urgency
    for text in (notice.summary, notice.body):
        assert not set(text) & set("<>&")
    assert notice.summary.startswith("A_b__c ")


# --- Notice -------------------------------------------------------------------------


def test_notice_rejects_an_unknown_urgency():
    with pytest.raises(ValueError, match="urgency"):
        Notice(summary="x", body="y", urgency="low")  # type: ignore[arg-type]


# --- send ---------------------------------------------------------------------------


def test_send_runs_notify_send_in_the_user_manager(ctx, fake_runner):
    fake_runner.on(SYSTEMD_RUN, Answer())

    sent = send(ctx, MEDIABOX_NOTICE)

    assert sent is True
    assert len(fake_runner.calls) == 1
    call = fake_runner.calls[0]
    assert call.argv == (
        SYSTEMD_RUN,
        "--user",
        "--wait",
        "--quiet",
        "--collect",
        NOTIFY_SEND,
        "-a",
        "steamos-mounter",
        "-u",
        "normal",
        "--",
        "MEDIABOX is dirty",
        "Mounted read-write with ntfs-3g at /run/media/deck/MEDIABOX."
        " Run chkdsk /f on it in Windows.",
    )
    assert call.user == 1000
    assert call.group == 1000
    assert call.env_extra == SESSION_ENV
    assert call.timeout == 15.0
    assert call.has_stdin is False


def test_send_passes_critical_urgency(ctx, fake_runner):
    fake_runner.on(SYSTEMD_RUN, Answer())

    send(
        ctx, Notice(summary="GAMES could not be mounted", body="b", urgency="critical")
    )

    argv = fake_runner.argvs[0]
    assert argv[argv.index("-u") + 1] == "critical"


def test_send_keeps_a_dash_summary_after_the_option_end(ctx, fake_runner):
    fake_runner.on(SYSTEMD_RUN, Answer())

    send(ctx, Notice(summary="-w is not a flag", body="--action=x", urgency="normal"))

    argv = fake_runner.argvs[0]
    assert argv[-3:] == ("--", "-w is not a flag", "--action=x")


def test_send_never_blocks_on_the_notification(ctx, fake_runner):
    fake_runner.on(SYSTEMD_RUN, Answer())

    send(ctx, MEDIABOX_NOTICE)

    notify_options = notify_send_options(fake_runner.argvs[0])
    assert not notify_options & {"-A", "--action", "-w", "--wait"}


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(
            Answer(returncode=1, stderr=b"Failed to connect to bus"), id="exit"
        ),
        pytest.param(Answer.timeout(), id="timeout"),
        pytest.param(Answer.missing(), id="missing"),
    ],
)
def test_failure_logged_outcome_unchanged(ctx, fake_runner, caplog, failure):
    fake_runner.on(SYSTEMD_RUN, failure)

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        sent = send(ctx, MEDIABOX_NOTICE)

    assert sent is False
    assert len(fake_runner.calls) == 1  # no retry, nothing else run
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].sm_fields["SM_EVENT"] == "notify"
    assert "notification not sent" in warnings[0].getMessage()


def test_failure_to_start_the_transport_is_logged(ctx, fake_runner, caplog):
    def refuse(cmd) -> None:
        raise PermissionError("Operation not permitted")

    fake_runner.on(SYSTEMD_RUN, Answer(), hook=refuse)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        sent = send(ctx, MEDIABOX_NOTICE)

    assert sent is False
    assert len(caplog.records) == 1
    assert caplog.records[0].sm_fields["SM_EVENT"] == "notify"


def test_send_refuses_a_secret_in_the_text(ctx, fake_runner):
    with SecretBytes(b"0123-secret-recovery-4567") as secret:
        leaky = Notice(
            summary="PERSONAL needs a key",
            body=f"key {secret.reveal().decode()}",
            urgency="critical",
        )
        with pytest.raises(SecretHandlingError):
            send(ctx, leaky)

    assert fake_runner.calls == []


# --- send: the time budget (a deadline on ctx.clock.monotonic()) ------------------


def test_send_takes_at_most_what_is_left_of_the_deadline(ctx, fake_runner, fake_clock):
    fake_runner.on(SYSTEMD_RUN, Answer())

    sent = send(ctx, MEDIABOX_NOTICE, deadline=fake_clock.monotonic() + 6.5)

    assert sent is True
    assert [call.timeout for call in fake_runner.calls] == [6.5]


def test_send_with_time_to_spare_keeps_its_own_15_s(ctx, fake_runner, fake_clock):
    fake_runner.on(SYSTEMD_RUN, Answer())

    sent = send(ctx, MEDIABOX_NOTICE, deadline=fake_clock.monotonic() + 60)

    assert sent is True
    assert [call.timeout for call in fake_runner.calls] == [15.0]


@pytest.mark.parametrize("left", [0.0, -3.0], ids=["at", "past"])
def test_send_out_of_time_is_skipped_with_one_warning(
    ctx, fake_runner, fake_clock, caplog, left
):
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        sent = send(ctx, MEDIABOX_NOTICE, deadline=fake_clock.monotonic() + left)

    assert sent is False
    assert fake_runner.calls == []
    [warning] = caplog.records
    assert warning.levelno == logging.WARNING
    assert warning.sm_fields["SM_EVENT"] == "notify"
    assert warning.getMessage() == (
        "notification not sent: no time left before the unit's start timeout"
    )


def test_out_of_time_is_false_while_time_is_left(ctx, fake_clock, caplog):
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        late = out_of_time(ctx, fake_clock.monotonic() + 0.1)

    assert late is False
    assert caplog.records == []


def test_out_of_time_without_a_deadline_is_never_late(ctx, fake_clock):
    fake_clock.advance(10_000)

    assert out_of_time(ctx, None) is False


# --- flag conformance against the Deck's help captures --------------------------


def help_has_option(help_text: str, option: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(option)}(?![\w-])", help_text) is not None


def systemd_run_options(argv: tuple[str, ...]) -> set[str]:
    own = argv[1 : argv.index(NOTIFY_SEND)]
    return {item.split("=")[0] for item in own if item.startswith("-")}


def notify_send_options(argv: tuple[str, ...]) -> set[str]:
    start = argv.index(NOTIFY_SEND) + 1
    own = argv[start : argv.index("--", start)]
    return {item.split("=")[0] for item in own if item.startswith("-")}


@pytest.mark.parametrize(
    ("help_fixture", "options_of"),
    [
        ("systemd-run-help.txt", systemd_run_options),
        ("notify-send-help.txt", notify_send_options),
    ],
)
def test_every_flag_appears_in_the_captured_help(
    ctx, fake_runner, help_fixture, options_of
):
    help_text = load_fixture(help_fixture).decode()
    fake_runner.on(SYSTEMD_RUN, Answer())

    send(ctx, MEDIABOX_NOTICE)

    options = options_of(fake_runner.argvs[0])
    assert options
    assert sorted(o for o in options if not help_has_option(help_text, o)) == []


def test_help_flag_check_catches_an_unknown_flag():
    # Negative control for the conformance test above.
    notify_help = load_fixture("notify-send-help.txt").decode()
    run_help = load_fixture("systemd-run-help.txt").decode()

    assert help_has_option(notify_help, "-A")
    assert help_has_option(notify_help, "--urgency")
    assert not help_has_option(notify_help, "--markup")
    assert help_has_option(run_help, "--collect")
    assert not help_has_option(run_help, "--wait-for-it")


def test_urgency_values_are_in_the_captured_help():
    notify_help = load_fixture("notify-send-help.txt").decode()

    assert "(low, normal, critical)" in notify_help
