"""The key dialog transport: kdialog in the session user's manager, over ``--pipe``.

Design Doc "Key Dialog Unit" (transport, outcome mapping, prompt text, one at
a time, unplug), DD-20, DD-21, IP-15, ADR-0005 D3 and D4 item 1. The key unit
calls this module only with a ``session.check(need_display=True)`` result
that says ``DESKTOP``; anything else raises ``ValueError`` and shows nothing.

- **Transport**: ``systemd-run --user --pipe --wait --quiet --collect`` with a
  unit name from the registry UUID, run as the session user and group (no
  supplementary groups) with only ``XDG_RUNTIME_DIR`` and
  ``DBUS_SESSION_BUS_ADDRESS`` added. The transient unit gets the verified
  ``DISPLAY``, ``QT_QPA_PLATFORM=xcb``, no ``WAYLAND_DISPLAY``, and
  ``XAUTHORITY`` only when the platform takes it from the X server (DD-20);
  otherwise the user manager's own value is inherited. stdin is
  ``/dev/null``; stdout goes into a ``SecretBytes`` with a 256-byte cap
  (``secret_stdout=True``) and stderr is discarded unread.
- **Password outcome**: exit 0 with output -> ``ENTERED`` (one trailing
  newline stripped, so the key is exactly what was typed); exit 0 with
  nothing (``SuccessExitStatus=1`` turns Cancel into 0, and an empty field
  prints only the newline) -> ``CANCELLED``; our 120 s timer ->
  ``TIMED_OUT``, then ``stop``; overflow, a NUL byte, kdialog's 134 abort on a
  bad display or any other status, a timeout of systemd-run itself included
  -> ``FAILED``, never ``CANCELLED``.
- **Save question** (DD-21): no ``SuccessExitStatus=1``, so only exit 0 is
  Yes; No, Escape, a close, the 60 s timer and every failure are No.
- **One at a time**: a leftover transient unit of the same name is stopped,
  and waited for, before a new dialog; a ``--no-block`` stop could still be
  running when ``systemd-run`` asks for the same name.

Only exit statuses, flags and outcomes are logged; the dialog output never is.
"""

import logging
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from steamos_mounter import config
from steamos_mounter.journal import fields
from steamos_mounter.runner import Command, CommandResult
from steamos_mounter.sensitive import SecretBytes
from steamos_mounter.session import SessionCheck, Verdict
from steamos_mounter.session_display import user_manager_env

if TYPE_CHECKING:
    from steamos_mounter.context import Context
    from steamos_mounter.model import Volume

PASSWORD_TIMEOUT: Final = 120.0
SAVE_TIMEOUT: Final = 60.0
KEY_OUTPUT_CAP: Final = 256
# The transient unit's own cap: our timer plus ten seconds.
PASSWORD_RUNTIME_MAX: Final = 130
SAVE_RUNTIME_MAX: Final = 70
STOP_TIMEOUT: Final = 15.0
UNIT_PREFIX: Final = "steamos-mounter-dialog-"
UNIT_SUFFIX: Final = ".service"
TITLE: Final = "steamos-mounter"
UNLOCK_PROMPT: Final = (
    "{name} is locked. {why} Enter the BitLocker password or the 48-digit recovery key."
)
# ``why`` is the NeedsKey reason that started the key unit.
WHY: Final = MappingProxyType(
    {
        "stored_key_rejected": "Its stored key did not work.",
        "stored_key_missing": "It has no stored key.",
    }
)
SAVE_PROMPT: Final = (
    "Save this key for next time? {name} will then unlock at plug-in without asking."
)
NUL: Final = b"\0"
NEWLINE: Final = b"\n"
NO_VERIFIED_DISPLAY: Final = "no dialog without a verified display"

log = logging.getLogger(__name__)


class Outcome(StrEnum):
    ENTERED = "entered"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed-out"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class PasswordAnswer:
    """The password dialog's outcome; ``key`` is set only for ``ENTERED``.

    The caller owns ``key`` and clears it (``with answer.key:``).
    """

    outcome: Outcome
    key: SecretBytes | None


def unit_name(uuid: str) -> str:
    """``steamos-mounter-dialog-<uuid>.service``; ``ValueError`` for a non-UUID."""
    return f"{_unit_base(uuid)}{UNIT_SUFFIX}"


def ask_password(
    ctx: "Context", session: SessionCheck, volume: "Volume", *, why: str
) -> PasswordAnswer:
    """Ask for ``volume``'s key on the verified display; ``why`` is a ``WHY`` key."""
    if why not in WHY:
        raise ValueError(f"no prompt for reason {why!r}")
    prompt = UNLOCK_PROMPT.format(name=volume.name, why=WHY[why])
    transport = _transport(
        ctx, session, volume.uuid, success_exit_1=True, runtime_max=PASSWORD_RUNTIME_MAX
    )
    argv = (*transport, ctx.platform.tools.kdialog, "--title", TITLE, "--password")
    result = _run_dialog(ctx, volume, (*argv, prompt), PASSWORD_TIMEOUT)
    answer = _password_answer(ctx, volume, result)
    _log_outcome(volume, "password", answer.outcome, result)
    return answer


def ask_save(ctx: "Context", session: SessionCheck, volume: "Volume") -> bool:
    """Ask whether to store the key that opened ``volume``; True only for Yes."""
    prompt = SAVE_PROMPT.format(name=volume.name)
    transport = _transport(
        ctx, session, volume.uuid, success_exit_1=False, runtime_max=SAVE_RUNTIME_MAX
    )
    argv = (*transport, ctx.platform.tools.kdialog, "--title", TITLE, "--yesno")
    result = _run_dialog(ctx, volume, (*argv, prompt), SAVE_TIMEOUT)
    if result is not None:
        _clear(result)
    if result is not None and result.timed_out:
        stop(ctx, volume.uuid)
    yes = result is not None and result.returncode == 0
    _log_outcome(volume, "save", "yes" if yes else "no", result)
    return yes


def stop(ctx: "Context", uuid: str) -> None:
    """``systemctl --user stop --no-block`` the dialog unit, as the session user.

    Best effort: a unit that is not loaded, or a failed request, is logged.
    """
    result = _stop(ctx, uuid, block=False)
    if result is not None and result.returncode == 0:
        log.debug("stop of %s requested", unit_name(uuid))


def _unit_base(uuid: str) -> str:
    if not any(form.fullmatch(uuid) for form in config.UUID_FORMS):
        raise ValueError(f"not a registry UUID: {uuid!r}")
    return f"{UNIT_PREFIX}{uuid}"


def _transport(
    ctx: "Context",
    session: SessionCheck,
    uuid: str,
    *,
    success_exit_1: bool,
    runtime_max: int,
) -> tuple[str, ...]:
    """The ``systemd-run`` part of a dialog argv, for a verified session only."""
    if session.verdict is not Verdict.DESKTOP or session.display is None:
        raise ValueError(NO_VERIFIED_DISPLAY)
    with_xauthority = ctx.platform.xauthority_from_xserver
    if with_xauthority and session.xauthority is None:
        raise ValueError(f"{NO_VERIFIED_DISPLAY}: no X server -auth path")
    argv = [
        ctx.platform.tools.systemd_run,
        "--user",
        "--pipe",
        "--wait",
        "--quiet",
        "--collect",
        f"--unit={_unit_base(uuid)}",
    ]
    if success_exit_1:
        argv.append("--property=SuccessExitStatus=1")
    argv += [
        f"--property=RuntimeMaxSec={runtime_max}",
        "--property=UnsetEnvironment=WAYLAND_DISPLAY",
        f"--setenv=DISPLAY={session.display}",
        "--setenv=QT_QPA_PLATFORM=xcb",
    ]
    if with_xauthority:
        argv.append(f"--setenv=XAUTHORITY={session.xauthority}")
    return tuple(argv)


def _run_dialog(
    ctx: "Context", volume: "Volume", argv: tuple[str, ...], timeout: float
) -> CommandResult | None:
    """Stop a leftover unit, then run the dialog; None when it could not start."""
    _stop(ctx, volume.uuid, block=True)
    user = ctx.platform.session_user()
    command = Command(
        argv=argv,
        timeout=timeout,
        env_extra=user_manager_env(user),
        user=user.uid,
        group=user.gid,
        secret_stdout=True,
        stdout_cap=KEY_OUTPUT_CAP,
        log_output=False,
    )
    try:
        return ctx.runner.run(command)
    except OSError as error:
        log.warning(
            "dialog for %s could not start: %s",
            volume.name,
            type(error).__name__,
            extra=fields(volume=volume.name, uuid=volume.uuid, event="key"),
        )
        return None


def _password_answer(
    ctx: "Context", volume: "Volume", result: CommandResult | None
) -> PasswordAnswer:
    """The outcome mapping; the raw output is cleared on every path."""
    if result is None:
        return PasswordAnswer(Outcome.FAILED, None)
    if result.timed_out:
        _clear(result)
        stop(ctx, volume.uuid)
        return PasswordAnswer(Outcome.TIMED_OUT, None)
    if result.returncode != 0 or result.overflow or result.secret is None:
        _clear(result)
        return PasswordAnswer(Outcome.FAILED, None)
    with result.secret as raw:
        output = raw.reveal()
    if NUL in output:
        log.debug("dialog output for %s holds a NUL byte", volume.name)
        return PasswordAnswer(Outcome.FAILED, None)
    key = output.removesuffix(NEWLINE)
    if not key:
        return PasswordAnswer(Outcome.CANCELLED, None)
    return PasswordAnswer(Outcome.ENTERED, SecretBytes(key))


def _clear(result: CommandResult) -> None:
    if result.secret is not None:
        result.secret.clear()


def _stop(ctx: "Context", uuid: str, *, block: bool) -> CommandResult | None:
    """``systemctl --user stop [--no-block] <unit>`` as the session user."""
    user = ctx.platform.session_user()
    no_block = () if block else ("--no-block",)
    argv = (ctx.platform.tools.systemctl, "--user", "stop", *no_block, unit_name(uuid))
    command = Command(
        argv=argv,
        timeout=STOP_TIMEOUT,
        env_extra=user_manager_env(user),
        user=user.uid,
        group=user.gid,
    )
    try:
        result = ctx.runner.run(command)
    except OSError as error:
        log.warning("stop of %s failed: %s", unit_name(uuid), type(error).__name__)
        return None
    if result.returncode != 0:
        # Exit 5: no such unit loaded, the usual case before a new dialog.
        log.debug(
            "stop of %s: exit %s, timed out %s",
            unit_name(uuid),
            result.returncode,
            result.timed_out,
        )
    return result


def _log_outcome(
    volume: "Volume", dialog: str, outcome: str, result: CommandResult | None
) -> None:
    """One line per dialog: the outcome and the transport facts, never output."""
    facts = "could not start"
    if result is not None:
        facts = (
            f"exit {result.returncode}, timed out {result.timed_out},"
            f" not found {result.not_found}, overflow {result.overflow}"
        )
    level = logging.WARNING if outcome == Outcome.FAILED else logging.INFO
    log.log(
        level,
        "%s dialog for %s: %s (%s)",
        dialog,
        volume.name,
        outcome,
        facts,
        extra=fields(volume=volume.name, uuid=volume.uuid, event="key"),
    )
