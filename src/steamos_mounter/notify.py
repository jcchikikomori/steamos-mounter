"""Desktop notifications for outcomes the owner has to act on.

Design Doc "Notifications", DD-19, AC-046, AC-047 and ADR-0005 D3 item 8.

- **Which** (``notice_for``): after a reconcile or key-unit outcome
  (``event`` ``"reconcile"`` or ``"key"``, the ``SM_EVENT`` of that outcome)
  for ``MountedRWDirty``, ``MountedRO``, ``MountedRW`` via ntfs-3g with a
  warning, ``MountFailed``, ``MountTimedOut``, ``UnlockFailed`` and
  ``NeedsKey`` with reason ``key_permissions`` or ``dialog_failed``. Never for
  any other ``NeedsKey`` (a started key unit's dialog replaces the
  notification; without a session there is nobody to tell), a cancel,
  ``MountedElsewhere``, ``Locked`` or a healthy state.
- **Text**: the summary names the volume; the body says what happened in
  plain words, then the view's next step. ``<``, ``>`` and ``&`` become
  ``_``, so Plasma's body markup cannot be injected through a name, a path or
  a warning. A secret never belongs in a notification: the runner refuses a
  command that carries one.
- **Transport** (``send``): ``notify-send`` run by ``systemd-run --user`` in
  the session user's manager, as that user, with ``XDG_RUNTIME_DIR`` and
  ``DBUS_SESSION_BUS_ADDRESS``; 15 s at most and never ``-A`` or ``-w``,
  which wait for the user. A failure is one WARNING with ``SM_EVENT=notify``
  and changes nothing else (AC-047).

The caller sends only when ``session.check(need_display=False)`` says
``DESKTOP`` (DD-19).
"""

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal

from steamos_mounter import state
from steamos_mounter.journal import fields
from steamos_mounter.model import VolumeState
from steamos_mounter.runner import Command

if TYPE_CHECKING:
    from steamos_mounter.context import Context
    from steamos_mounter.state import VolumeView

APP_NAME: Final = "steamos-mounter"
SEND_TIMEOUT: Final = 15.0
NOTIFY_EVENTS: Final = frozenset({"reconcile", "key"})
NTFS3G_DRIVER: Final = "ntfs-3g"
MARKUP_CHARACTERS: Final = str.maketrans(dict.fromkeys("<>&", "_"))
NOTIFY_FAILED: Final = "notification not sent"

Urgency = Literal["normal", "critical"]

_NORMAL: Final[Urgency] = "normal"
_CRITICAL: Final[Urgency] = "critical"
URGENCIES: Final = frozenset({_NORMAL, _CRITICAL})
_MOUNT_PROBLEM: Final = "{name} could not be mounted"
_NEEDS_KEY: Final = "{name} needs a key"

# NeedsKey reasons that get a notification; every other one has a dialog
# coming (the key unit was started) or nobody to tell.
_NEEDS_KEY_PROBLEMS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "key_permissions": (
            "The stored key file has unsafe permissions or an unexpected owner."
        ),
        "dialog_failed": "The key dialog could not be shown.",
    }
)

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Notice:
    summary: str
    body: str
    urgency: Urgency

    def __post_init__(self) -> None:
        if self.urgency not in URGENCIES:
            raise ValueError(f"unknown notification urgency {self.urgency!r}")


def notice_for(view: "VolumeView", *, event: str) -> Notice | None:
    """The notification for ``view`` after ``event``, or None when there is none."""
    if event not in NOTIFY_EVENTS:
        return None
    found = _summary_problem_urgency(view)
    if found is None:
        return None
    summary, problem, urgency = found
    step = "" if view.next_step == state.NO_NEXT_STEP else view.next_step
    body = " ".join(part for part in (problem, step) if part)
    return Notice(
        summary=_without_markup(summary.format(name=view.name)),
        body=_without_markup(body),
        urgency=urgency,
    )


def send(ctx: "Context", notice: Notice) -> bool:
    """Show ``notice`` in the session user's desktop; False when that failed.

    A failure is logged at WARNING with ``SM_EVENT=notify`` and is otherwise
    ignored (AC-047). A secret in the text raises ``SecretHandlingError``.
    """
    user = ctx.platform.session_user()
    tools = ctx.platform.tools
    argv = (
        tools.systemd_run,
        "--user",
        "--wait",
        "--quiet",
        "--collect",
        tools.notify_send,
        "-a",
        APP_NAME,
        "-u",
        notice.urgency,
        "--",
        notice.summary,
        notice.body,
    )
    command = Command(
        argv=argv,
        timeout=SEND_TIMEOUT,
        env_extra={
            "XDG_RUNTIME_DIR": user.runtime_dir,
            "DBUS_SESSION_BUS_ADDRESS": user.bus_address,
        },
        user=user.uid,
        group=user.gid,
    )
    try:
        result = ctx.runner.run(command)
    except OSError as error:
        _log_failure(f"{type(error).__name__}: {error}")
        return False
    if result.returncode == 0:
        return True
    _log_failure(
        f"exit {result.returncode}, timed out {result.timed_out}, not found"
        f" {result.not_found}: {result.err_text().strip()}"
    )
    return False


def _summary_problem_urgency(
    view: "VolumeView",
) -> tuple[str, str, Urgency] | None:
    """The summary template, the problem sentence and the urgency, if notified."""
    match view.state:
        case VolumeState.MOUNTED_RW_DIRTY:
            return (
                "{name} is dirty",
                f"Mounted read-write with ntfs-3g at {view.path}.",
                _NORMAL,
            )
        case VolumeState.MOUNTED_RO:
            return "{name} is read-only", _read_only_problem(view), _NORMAL
        case VolumeState.MOUNTED_RW if view.driver == NTFS3G_DRIVER and view.warning:
            return (
                "{name} is mounted with ntfs-3g",
                f"Mounted read-write with ntfs-3g at {view.path}. {view.warning}",
                _NORMAL,
            )
        case VolumeState.MOUNT_FAILED | VolumeState.MOUNT_TIMED_OUT:
            words = state.words(view.state, view.reason)
            return _MOUNT_PROBLEM, f"{words[:1].upper()}{words[1:]}.", _CRITICAL
        case VolumeState.UNLOCK_FAILED:
            return "{name} did not unlock", "The key was rejected.", _CRITICAL
        case VolumeState.NEEDS_KEY if view.reason in _NEEDS_KEY_PROBLEMS:
            return _NEEDS_KEY, _NEEDS_KEY_PROBLEMS[view.reason], _CRITICAL
        case _:
            return None


def _read_only_problem(view: "VolumeView") -> str:
    if view.reason == "unsafe":
        return (
            f"Mounted read-only at {view.path} because it is in an"
            f" {state.UNSAFE_STATE}."
        )
    return f"Mounted read-only at {view.path}."


def _without_markup(text: str) -> str:
    return text.translate(MARKUP_CHARACTERS)


def _log_failure(detail: str) -> None:
    log.warning("%s: %s", NOTIFY_FAILED, detail, extra=fields(event="notify"))
