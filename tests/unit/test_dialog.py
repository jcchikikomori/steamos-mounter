"""The key dialog transport: argv, outcome mapping, stop, and the secret output.

Design Doc "Key Dialog Unit" (transport, outcome mapping, prompt text, one at
a time, unplug), DD-20, DD-21, IP-15 and the ADR-0005 guidance list: entered,
cancelled, empty, oversized, NUL byte, timeout, transport failure, kdialog's
abort on a bad display and a stale display. The fake runner stands in for
``systemd-run`` and ``systemctl``; like the real one it wraps a
``secret_stdout`` call's output in ``SecretBytes``, leaves stderr empty and
applies the 256-byte cap. The argv is checked byte for byte, and every flag
against the Deck's ``kdialog --help`` and ``systemd-run --help`` captures.

Key assertions compare booleans computed beforehand, so a failing test never
prints a key.
"""

import dataclasses
import logging
import re

import pytest

from steamos_mounter import dialog
from steamos_mounter import session as session_module
from steamos_mounter.dialog import Outcome, PasswordAnswer
from steamos_mounter.model import Volume
from steamos_mounter.runner import Command, CommandResult
from steamos_mounter.sensitive import live_secrets
from steamos_mounter.session import SessionCheck, Verdict
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture
from tests.helpers.proc_tree import XORG_AUTH, XORG_PID, ProcTree

SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"
KDIALOG = "/usr/bin/kdialog"
PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
DIALOG_UNIT = f"steamos-mounter-dialog-{PERSONAL_UUID}"
DIALOG_SERVICE = f"{DIALOG_UNIT}.service"
TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"
SESSION_ENV = {
    "XDG_RUNTIME_DIR": "/run/user/1000",
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
}
PASSWORD_PROMPT = (
    "PERSONAL is locked. Its stored key did not work. Enter the BitLocker "
    "password or the 48-digit recovery key."
)
NO_KEY_PROMPT = (
    "PERSONAL is locked. It has no stored key. Enter the BitLocker "
    "password or the 48-digit recovery key."
)
SAVE_PROMPT = (
    "Save this key for next time? PERSONAL will then unlock at plug-in without asking."
)
PASSWORD_ARGV = (
    SYSTEMD_RUN,
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
    KDIALOG,
    "--title",
    "steamos-mounter",
    "--password",
    PASSWORD_PROMPT,
)
SAVE_ARGV = (
    SYSTEMD_RUN,
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
    KDIALOG,
    "--title",
    "steamos-mounter",
    "--yesno",
    SAVE_PROMPT,
)
LEFTOVER_STOP = (SYSTEMCTL, "--user", "stop", DIALOG_SERVICE)
NO_BLOCK_STOP = (SYSTEMCTL, "--user", "stop", "--no-block", DIALOG_SERVICE)
TRANSPORT = (SYSTEMD_RUN, "--user", "--pipe")
NOT_LOADED = Answer(returncode=5, stderr=b"Unit not loaded.")
LOGGER = "steamos_mounter.dialog"

PERSONAL = Volume(
    name="PERSONAL",
    uuid=PERSONAL_UUID,
    path="/run/media/deck/PERSONAL",
    fstype="BitLocker",
    drivers=None,
    nosuid=True,
    nodev=True,
)
DESKTOP_SESSION = SessionCheck(
    verdict=Verdict.DESKTOP,
    session_id="5",
    scope="session-5.scope",
    display=":0",
    xorg_pid=XORG_PID,
    xauthority=None,
    detail={},
)


def script_dialog(fake_runner, *answers: Answer) -> None:
    fake_runner.on((SYSTEMCTL, "--user", "stop"), NOT_LOADED, repeat=True)
    fake_runner.on(TRANSPORT, *answers)


def ask(ctx, session=DESKTOP_SESSION, why="stored_key_rejected") -> PasswordAnswer:
    return dialog.ask_password(ctx, session, PERSONAL, why=why)


def holds(answer: PasswordAnswer, expected: bytes) -> bool:
    return answer.key is not None and answer.key.reveal() == expected


def raw_output_live(output: bytes) -> bool:
    return output in live_secrets()


def transport_calls(fake_runner):
    return [call for call in fake_runner.calls if call.argv[0] == SYSTEMD_RUN]


def with_xauthority_flag(ctx):
    platform = dataclasses.replace(ctx.platform, xauthority_from_xserver=True)
    return dataclasses.replace(ctx, platform=platform)


# --- unit_name ---------------------------------------------------------------------


def test_unit_name_is_derived_from_the_registry_uuid():
    assert dialog.unit_name(PERSONAL_UUID) == DIALOG_SERVICE


@pytest.mark.parametrize("uuid", ["01D95F1575592A30", "1234-ABCD"])
def test_unit_name_takes_every_registry_uuid_form(uuid):
    assert dialog.unit_name(uuid) == f"steamos-mounter-dialog-{uuid}.service"


@pytest.mark.parametrize(
    "uuid", ["", "-rf", "../etc", "abc def", f"{PERSONAL_UUID}.service", "x" * 16]
)
def test_unit_name_refuses_anything_but_a_uuid(uuid):
    with pytest.raises(ValueError, match="UUID"):
        dialog.unit_name(uuid)


# --- the password transport: argv and how it runs ----------------------------------


def test_password_argv_is_byte_exact(ctx, fake_runner):
    script_dialog(fake_runner, Answer(stdout=TEST_KEY + b"\n"))

    answer = ask(ctx)

    [call] = transport_calls(fake_runner)
    assert call.argv == PASSWORD_ARGV
    answer.key.clear()


def test_password_prompt_for_a_missing_key(ctx, fake_runner):
    script_dialog(fake_runner, Answer())

    ask(ctx, why="stored_key_missing")

    [call] = transport_calls(fake_runner)
    assert call.argv[-1] == NO_KEY_PROMPT
    assert call.argv[:-1] == PASSWORD_ARGV[:-1]


@pytest.mark.parametrize("why", ["dialog_failed", "", "Its stored key did not work."])
def test_unknown_reason_is_refused_before_anything_runs(ctx, fake_runner, why):
    with pytest.raises(ValueError, match="no prompt"):
        ask(ctx, why=why)

    assert fake_runner.calls == []


def test_password_dialog_runs_as_the_session_user_with_a_secret_stdout(
    ctx, fake_runner
):
    script_dialog(fake_runner, Answer())

    ask(ctx)

    [call] = transport_calls(fake_runner)
    assert (call.user, call.group) == (1000, 1000)
    assert call.env_extra == SESSION_ENV
    assert call.secret_stdout is True
    assert call.has_stdin is False
    assert call.log_output is False
    assert call.timeout == dialog.PASSWORD_TIMEOUT == 120.0


def test_leftover_unit_is_stopped_and_waited_for_first(ctx, fake_runner):
    script_dialog(fake_runner, Answer())

    ask(ctx)

    assert fake_runner.argvs == [LEFTOVER_STOP, PASSWORD_ARGV]
    stop_call = fake_runner.calls[0]
    assert (stop_call.user, stop_call.group) == (1000, 1000)
    assert stop_call.env_extra == SESSION_ENV


def test_dialog_runs_even_when_the_leftover_stop_fails(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "--user", "stop"), Answer.timeout())
    fake_runner.on(TRANSPORT, Answer())

    answer = ask(ctx)

    assert answer.outcome is Outcome.CANCELLED
    assert fake_runner.argvs[-1] == PASSWORD_ARGV


def test_leftover_stop_that_cannot_start_does_not_stop_the_dialog(ctx, fake_runner):
    def refuse(_cmd):
        raise PermissionError("forced by the test")

    fake_runner.on((SYSTEMCTL, "--user", "stop"), Answer(), hook=refuse)
    fake_runner.on(TRANSPORT, Answer())

    answer = ask(ctx)

    assert answer.outcome is Outcome.CANCELLED


def test_display_comes_from_the_verified_session(ctx, fake_runner):
    script_dialog(fake_runner, Answer())
    on_x1 = dataclasses.replace(DESKTOP_SESSION, display=":1")

    ask(ctx, session=on_x1)

    [call] = transport_calls(fake_runner)
    assert "--setenv=DISPLAY=:1" in call.argv
    assert "--setenv=DISPLAY=:0" not in call.argv


# --- XAUTHORITY only with the platform flag (DD-20) --------------------------------


def test_xauthority_is_set_only_with_the_platform_flag(ctx, fake_runner):
    script_dialog(fake_runner, Answer())
    session = dataclasses.replace(DESKTOP_SESSION, xauthority=XORG_AUTH)

    ask(with_xauthority_flag(ctx), session=session)

    [call] = transport_calls(fake_runner)
    expected = (
        *PASSWORD_ARGV[:12],
        f"--setenv=XAUTHORITY={XORG_AUTH}",
        *PASSWORD_ARGV[12:],
    )
    assert call.argv == expected


def test_without_the_flag_xauthority_is_inherited_not_set(ctx, fake_runner):
    script_dialog(fake_runner, Answer())
    session = dataclasses.replace(DESKTOP_SESSION, xauthority=XORG_AUTH)

    ask(ctx, session=session)

    [call] = transport_calls(fake_runner)
    assert call.argv == PASSWORD_ARGV
    assert not any("XAUTHORITY" in item for item in call.argv)
    assert "XAUTHORITY" not in call.env_extra


def test_flag_without_an_xauthority_path_shows_nothing(ctx, fake_runner):
    with pytest.raises(ValueError, match="-auth"):
        ask(with_xauthority_flag(ctx))

    assert fake_runner.calls == []


def test_save_question_carries_xauthority_with_the_flag(ctx, fake_runner):
    script_dialog(fake_runner, Answer())
    session = dataclasses.replace(DESKTOP_SESSION, xauthority=XORG_AUTH)

    dialog.ask_save(with_xauthority_flag(ctx), session, PERSONAL)

    [call] = transport_calls(fake_runner)
    assert f"--setenv=XAUTHORITY={XORG_AUTH}" in call.argv


# --- no dialog without a verified display (stale display, AC-076) ------------------


@pytest.mark.parametrize(
    "session",
    [
        dataclasses.replace(DESKTOP_SESSION, display=None, xorg_pid=None),
        dataclasses.replace(DESKTOP_SESSION, verdict=Verdict.NOT_SURE),
        dataclasses.replace(DESKTOP_SESSION, verdict=Verdict.NONE, display=None),
    ],
    ids=["logind-only check", "not sure", "no session"],
)
def test_no_dialog_without_a_verified_display(ctx, fake_runner, session):
    with pytest.raises(ValueError, match="verified display"):
        ask(ctx, session=session)
    with pytest.raises(ValueError, match="verified display"):
        dialog.ask_save(ctx, session, PERSONAL)

    assert fake_runner.calls == []


def test_stale_display_from_the_session_check_shows_no_dialog(
    ctx, fake_runner, tmp_path
):
    # The session check itself (stale X1, no listener) refuses the display.
    ProcTree(tmp_path).desktop()
    fake_runner.on(("/usr/bin/loginctl", "show-user"), "loginctl-user-deck-display.txt")
    fake_runner.on(("/usr/bin/loginctl", "show-seat"), "loginctl-seat-seat0-active.txt")
    fake_runner.on(
        ("/usr/bin/loginctl", "show-session"), "loginctl-session-5-properties.txt"
    )
    fake_runner.on(
        (SYSTEMCTL, "--user", "show-environment"), Answer(stdout=b"DISPLAY=:1\n")
    )
    stale = session_module.check(ctx, need_display=True)

    with pytest.raises(ValueError, match="verified display"):
        ask(ctx, session=stale)

    assert stale.verdict is Verdict.NOT_SURE
    assert transport_calls(fake_runner) == []


# --- password outcome mapping ------------------------------------------------------


def test_entered_key_loses_exactly_one_trailing_newline(ctx, fake_runner):
    script_dialog(fake_runner, Answer(stdout=TEST_KEY + b"\n"))

    answer = ask(ctx)

    entered = answer.outcome is Outcome.ENTERED
    exact = holds(answer, TEST_KEY)
    raw_cleared = not raw_output_live(TEST_KEY + b"\n")
    answer.key.clear()
    assert entered
    assert exact
    assert raw_cleared


def test_entered_key_without_a_newline_is_kept_whole(ctx, fake_runner):
    script_dialog(fake_runner, Answer(stdout=TEST_KEY))

    answer = ask(ctx)

    exact = holds(answer, TEST_KEY)
    answer.key.clear()
    assert answer.outcome is Outcome.ENTERED
    assert exact


def test_only_one_newline_is_stripped(ctx, fake_runner):
    script_dialog(fake_runner, Answer(stdout=TEST_KEY + b"\n\n"))

    answer = ask(ctx)

    exact = holds(answer, TEST_KEY + b"\n")
    answer.key.clear()
    assert exact


@pytest.mark.parametrize("stdout", [b"", b"\n"], ids=["cancel", "empty field"])
def test_exit_zero_without_a_key_is_cancelled(ctx, fake_runner, stdout):
    script_dialog(fake_runner, Answer(stdout=stdout))

    answer = ask(ctx)

    assert answer == PasswordAnswer(Outcome.CANCELLED, None)


def test_output_at_the_cap_is_accepted(ctx, fake_runner):
    script_dialog(fake_runner, Answer(stdout=b"k" * dialog.KEY_OUTPUT_CAP))

    answer = ask(ctx)

    exact = holds(answer, b"k" * 256)
    answer.key.clear()
    assert answer.outcome is Outcome.ENTERED
    assert exact


@pytest.mark.parametrize("size", [257, 4096])
def test_oversized_output_is_failed(ctx, fake_runner, size):
    script_dialog(fake_runner, Answer(stdout=b"k" * size))

    answer = ask(ctx)

    assert answer == PasswordAnswer(Outcome.FAILED, None)
    assert not raw_output_live(b"k" * 256)


@pytest.mark.parametrize("stdout", [b"\0", b"abc\0def\n", TEST_KEY + b"\0\n", b"\n\0"])
def test_nul_byte_is_failed(ctx, fake_runner, stdout):
    script_dialog(fake_runner, Answer(stdout=stdout))

    answer = ask(ctx)

    assert answer == PasswordAnswer(Outcome.FAILED, None)
    assert not raw_output_live(stdout)


def test_timeout_maps_to_timed_out_then_stops_the_unit(ctx, fake_runner):
    script_dialog(fake_runner, Answer.timeout())

    answer = ask(ctx)

    assert answer == PasswordAnswer(Outcome.TIMED_OUT, None)
    assert fake_runner.argvs == [LEFTOVER_STOP, PASSWORD_ARGV, NO_BLOCK_STOP]
    stop_call = fake_runner.calls[-1]
    assert (stop_call.user, stop_call.group) == (1000, 1000)
    assert stop_call.env_extra == SESSION_ENV


@pytest.mark.parametrize(
    "result",
    [
        Answer(returncode=134),  # kdialog abort on a bad display
        Answer(returncode=1),  # systemd-run: failed to connect to the bus
        Answer(returncode=2),
        Answer(returncode=255),
        Answer(returncode=1, stdout=TEST_KEY + b"\n"),
        Answer(returncode=134, stdout=b"\n"),
        Answer.missing(),  # transport binary missing
    ],
    ids=[
        "abort-134",
        "exit-1",
        "exit-2",
        "exit-255",
        "exit-1-with-key",
        "abort-134-empty",
        "not-found",
    ],
)
def test_any_other_status_is_failed_never_cancelled(ctx, fake_runner, result):
    script_dialog(fake_runner, result)

    answer = ask(ctx)

    assert answer == PasswordAnswer(Outcome.FAILED, None)
    assert not raw_output_live(TEST_KEY + b"\n")


class NotFoundRunner:
    """``SubprocessRunner``'s answer for a missing binary: no secret at all."""

    def __init__(self) -> None:
        self.argvs: list[tuple[str, ...]] = []

    def run(self, cmd: Command) -> CommandResult:
        self.argvs.append(tuple(cmd.argv))
        return CommandResult(
            argv=tuple(cmd.argv),
            returncode=None,
            stdout=b"",
            stderr=b"",
            secret=None,
            timed_out=False,
            not_found=True,
            overflow=False,
        )


def test_missing_transport_without_a_secret_is_failed(ctx):
    runner = NotFoundRunner()

    answer = ask(dataclasses.replace(ctx, runner=runner))

    assert answer == PasswordAnswer(Outcome.FAILED, None)
    assert runner.argvs == [LEFTOVER_STOP, PASSWORD_ARGV]


def test_transport_that_cannot_start_is_failed(ctx, fake_runner):
    def refuse(_cmd):
        raise PermissionError("forced by the test")

    fake_runner.on((SYSTEMCTL, "--user", "stop"), NOT_LOADED)
    fake_runner.on(TRANSPORT, Answer(), hook=refuse)

    answer = ask(ctx)

    assert answer == PasswordAnswer(Outcome.FAILED, None)


def test_outcome_spellings():
    assert [str(outcome) for outcome in Outcome] == [
        "entered",
        "cancelled",
        "timed-out",
        "failed",
    ]


# --- logging: outcome and transport facts, never the output ------------------------


def test_failed_dialog_logs_the_status_at_warning(ctx, fake_runner, caplog):
    script_dialog(fake_runner, Answer(returncode=134))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        ask(ctx)

    [line] = [r for r in caplog.records if r.levelno >= logging.INFO]
    assert line.levelname == "WARNING"
    assert line.getMessage() == (
        "password dialog for PERSONAL: failed (exit 134, timed out False,"
        " not found False, overflow False)"
    )
    assert line.sm_fields["SM_EVENT"] == "key"
    assert line.sm_fields["SM_UUID"] == PERSONAL_UUID


def test_entered_key_never_reaches_the_log(ctx, fake_runner, caplog):
    script_dialog(fake_runner, Answer(stdout=TEST_KEY + b"\n"))

    with caplog.at_level(logging.DEBUG):
        answer = ask(ctx)

    in_log = TEST_KEY.decode() in caplog.text
    in_repr = TEST_KEY.decode() in repr(answer)
    answer.key.clear()
    assert not in_log
    assert not in_repr
    assert "password dialog for PERSONAL: entered" in caplog.text


def test_dialog_that_could_not_start_logs_why(ctx, fake_runner, caplog):
    def refuse(_cmd):
        raise PermissionError("forced by the test")

    fake_runner.on((SYSTEMCTL, "--user", "stop"), NOT_LOADED)
    fake_runner.on(TRANSPORT, Answer(), hook=refuse)

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        ask(ctx)

    messages = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert messages == [
        "dialog for PERSONAL could not start: PermissionError",
        "password dialog for PERSONAL: failed (could not start)",
    ]


# --- the save question (DD-21) -----------------------------------------------------


def test_save_argv_is_byte_exact_without_success_exit_status(ctx, fake_runner):
    script_dialog(fake_runner, Answer())

    dialog.ask_save(ctx, DESKTOP_SESSION, PERSONAL)

    [call] = transport_calls(fake_runner)
    assert call.argv == SAVE_ARGV
    assert not any("SuccessExitStatus" in item for item in call.argv)
    assert fake_runner.argvs[0] == LEFTOVER_STOP


def test_save_question_runs_like_the_password_dialog(ctx, fake_runner):
    script_dialog(fake_runner, Answer())

    dialog.ask_save(ctx, DESKTOP_SESSION, PERSONAL)

    [call] = transport_calls(fake_runner)
    assert (call.user, call.group, call.env_extra) == (1000, 1000, SESSION_ENV)
    assert call.secret_stdout is True
    assert call.log_output is False
    assert call.timeout == dialog.SAVE_TIMEOUT == 60.0


def test_only_exit_zero_is_yes(ctx, fake_runner):
    script_dialog(fake_runner, Answer())

    assert dialog.ask_save(ctx, DESKTOP_SESSION, PERSONAL) is True


@pytest.mark.parametrize(
    "result",
    [
        Answer(returncode=1),  # No, Escape, window closed
        Answer(returncode=134),
        Answer(returncode=2),
        Answer.missing(),
    ],
)
def test_anything_else_is_no(ctx, fake_runner, result):
    script_dialog(fake_runner, result)

    assert dialog.ask_save(ctx, DESKTOP_SESSION, PERSONAL) is False


def test_save_timeout_is_no_and_stops_the_unit(ctx, fake_runner):
    script_dialog(fake_runner, Answer.timeout())

    assert dialog.ask_save(ctx, DESKTOP_SESSION, PERSONAL) is False
    assert fake_runner.argvs == [LEFTOVER_STOP, SAVE_ARGV, NO_BLOCK_STOP]


def test_save_that_cannot_start_is_no(ctx, fake_runner):
    def refuse(_cmd):
        raise PermissionError("forced by the test")

    fake_runner.on((SYSTEMCTL, "--user", "stop"), NOT_LOADED)
    fake_runner.on(TRANSPORT, Answer(), hook=refuse)

    assert dialog.ask_save(ctx, DESKTOP_SESSION, PERSONAL) is False


def test_save_output_is_cleared(ctx, fake_runner):
    script_dialog(fake_runner, Answer(stdout=b"unexpected output\n"))

    dialog.ask_save(ctx, DESKTOP_SESSION, PERSONAL)

    assert not raw_output_live(b"unexpected output\n")


def test_save_answer_is_logged(ctx, fake_runner, caplog):
    script_dialog(fake_runner, Answer(returncode=1))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        dialog.ask_save(ctx, DESKTOP_SESSION, PERSONAL)

    assert "save dialog for PERSONAL: no (exit 1," in caplog.text


# --- stop --------------------------------------------------------------------------


def test_stop_is_a_no_block_user_stop_as_the_session_user(ctx, fake_runner):
    fake_runner.on(NO_BLOCK_STOP, Answer())

    assert dialog.stop(ctx, PERSONAL_UUID) is None

    [call] = fake_runner.calls
    assert call.argv == NO_BLOCK_STOP
    assert (call.user, call.group, call.env_extra) == (1000, 1000, SESSION_ENV)


@pytest.mark.parametrize("result", [NOT_LOADED, Answer.timeout(), Answer.missing()])
def test_stop_failures_are_logged_not_raised(ctx, fake_runner, caplog, result):
    fake_runner.on(NO_BLOCK_STOP, result)

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        dialog.stop(ctx, PERSONAL_UUID)

    assert f"stop of {DIALOG_SERVICE}: exit" in caplog.text


def test_stop_that_cannot_start_is_logged(ctx, fake_runner, caplog):
    def refuse(_cmd):
        raise PermissionError("forced by the test")

    fake_runner.on(NO_BLOCK_STOP, Answer(), hook=refuse)

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        dialog.stop(ctx, PERSONAL_UUID)

    assert f"stop of {DIALOG_SERVICE} failed: PermissionError" in caplog.text


def test_stop_refuses_a_non_uuid(ctx, fake_runner):
    with pytest.raises(ValueError, match="UUID"):
        dialog.stop(ctx, "--all")

    assert fake_runner.calls == []


# --- flag conformance with the Deck's help captures --------------------------------


def help_options(capture: str) -> set[str]:
    """Long options the help text lists, without their ``=VALUE`` part."""
    text = load_fixture(capture).decode("utf-8")
    return set(re.findall(r"(?m)^\s+(?:-\w,?\s+)?(--[a-z][a-z-]*)", text))


def used_options(argv: tuple[str, ...]) -> set[str]:
    return {item.partition("=")[0] for item in argv if item.startswith("--")}


@pytest.mark.parametrize("argv", [PASSWORD_ARGV, SAVE_ARGV], ids=["password", "save"])
def test_every_systemd_run_flag_is_in_the_help_capture(argv):
    kdialog_at = argv.index(KDIALOG)

    used = used_options(argv[:kdialog_at])

    assert used == {
        "--user",
        "--pipe",
        "--wait",
        "--quiet",
        "--collect",
        "--unit",
        "--property",
        "--setenv",
    }
    assert used <= help_options("systemd-run-help.txt")


@pytest.mark.parametrize("argv", [PASSWORD_ARGV, SAVE_ARGV], ids=["password", "save"])
def test_every_kdialog_flag_is_in_the_help_capture(argv):
    kdialog_at = argv.index(KDIALOG)

    used = used_options(argv[kdialog_at + 1 :])

    assert used in ({"--title", "--password"}, {"--title", "--yesno"})
    assert used <= help_options("kdialog-help.txt")


def test_help_parser_reads_both_captures():
    systemd_run = help_options("systemd-run-help.txt")
    kdialog = help_options("kdialog-help.txt")

    assert {"--pipe", "--setenv", "--property", "--machine"} <= systemd_run
    assert {"--password", "--yesno", "--title", "--inputbox"} <= kdialog
    assert "--secret-flag" not in systemd_run | kdialog
