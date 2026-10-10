"""Is the session user at a Desktop Mode session on this seat? (logind half)

Design Doc "Key Dialog Unit" (session check), "Notifications", IP-14,
ADR-0005 D2 and DD-19. ``check`` asks logind three questions through the
runner, all as the caller (``loginctl show-*`` needs no privilege):

1. ``loginctl show-user <user> -p Display``: the user's primary graphical
   session; absent or empty means there is none (``NONE``).
2. ``loginctl show-seat <seat> -p ActiveSession`` must name that session.
3. ``loginctl show-session <id> -p ...`` must match the allow-list: the
   session user's name, the platform's seat, class, desktops and session types
   (``SessionAllowList``), plus logind's own "in front of the user" values
   ``Active=yes``, ``Remote=no`` and ``State=active``.

Any doubt (a mismatch, ``Type=wayland`` in v1, an unusable session id, a
failed query) is ``NOT_SURE``, and one NOTICE line carries the property
values (AC-076): a missed dialog or notification is better than one in the
wrong place.

A caller with a time budget passes ``deadline`` (a ``ctx.clock.monotonic()``
time): each query then gets at most what is left of it, and once nothing is
left no query runs and the verdict is ``NOT_SURE``.

The display half (the user manager's ``DISPLAY``, the X listener in the
session's scope, ``need_display=True``) is not built yet: asking for it raises
``NotImplementedError``. Notifications only need the logind half (DD-19).
"""

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from steamos_mounter.journal import NOTICE
from steamos_mounter.platforms.base import SessionAllowList
from steamos_mounter.runner import Command, CommandResult
from steamos_mounter.systemd import parse_show

if TYPE_CHECKING:
    from steamos_mounter.context import Context

QUERY_TIMEOUT: Final = 10.0
SESSION_PROPERTIES: Final = (
    "Name",
    "Seat",
    "Active",
    "Remote",
    "Class",
    "Type",
    "State",
    "Desktop",
    "Scope",
    "Display",
    "Service",
    "VTNr",
)
# logind's values for a local session in front of the user. Facts about logind
# itself, not about the platform, so they are not part of SessionAllowList.
LOGIND_IN_FRONT: Final[Mapping[str, str]] = MappingProxyType(
    {"Active": "yes", "Remote": "no", "State": "active"}
)
# A logind session id ("5", "c1"): never empty, never an option, never a path.
SESSION_ID: Final = re.compile(r"[A-Za-z0-9]+")
NOT_RECOGNIZED: Final = "session not recognized"
DISPLAY_HALF_MISSING: Final = (
    "the display half of the session check (user manager DISPLAY, X listener)"
    " is not built yet"
)

log = logging.getLogger(__name__)


class Verdict(StrEnum):
    DESKTOP = "desktop"
    NONE = "none"
    NOT_SURE = "not-sure"


@dataclass(frozen=True, slots=True)
class SessionCheck:
    """What ``check`` found. ``detail`` holds the logind values it decided on."""

    verdict: Verdict
    session_id: str | None
    scope: str | None
    display: str | None
    xorg_pid: int | None
    xauthority: str | None
    detail: Mapping[str, str]


class _Props(dict[str, str]):
    """A parsed property dict where an absent property reads as ``""``."""

    def __missing__(self, key: str) -> str:
        return ""


def parse_props(text: str) -> dict[str, str]:
    """``loginctl show-*`` output as a dict; an absent key reads as ``""``.

    loginctl prints properties with systemctl's printer, so the parsing
    (``Name=value`` lines, quoted values unquoted) is ``systemd.parse_show``.
    The full ``show-session`` omits an empty ``Display`` while ``-p Display``
    prints ``Display=``; both read as ``""`` here, and reading an absent key
    adds nothing to the dict.
    """
    return _Props(parse_show(text))


def check(
    ctx: "Context", *, need_display: bool, deadline: float | None = None
) -> SessionCheck:
    """The session verdict for the platform's session user and seat.

    ``need_display=True`` (the key dialog) raises ``NotImplementedError``
    until the display half lands; no Phase 3 caller asks for it. With a
    ``deadline`` no query runs past it (``QUERY_TIMEOUT`` at most each).
    """
    if need_display:
        raise NotImplementedError(DISPLAY_HALF_MISSING)
    user_name = ctx.platform.session_user().name
    allow_list = ctx.platform.allow_list
    queries = _Queries(ctx, deadline)

    user = queries.run("show-user", user_name, ("Display",))
    if not isinstance(user, dict):
        return _unanswered(user, None, "show-user")
    session_id = user["Display"]
    if not session_id:
        log.info("%s has no graphical session", user_name)
        return _verdict(Verdict.NONE, None, {"Display": ""})
    if SESSION_ID.fullmatch(session_id) is None:
        return _not_sure(None, {"Display": session_id}, ("Display",))

    seat = queries.run("show-seat", allow_list.seat, ("ActiveSession",))
    if not isinstance(seat, dict):
        return _unanswered(seat, session_id, "show-seat")
    if seat["ActiveSession"] != session_id:
        detail = {"Display": session_id, "ActiveSession": seat["ActiveSession"]}
        return _not_sure(session_id, detail, ("ActiveSession",))

    props = queries.run("show-session", session_id, SESSION_PROPERTIES)
    if not isinstance(props, dict):
        return _unanswered(props, session_id, "show-session")
    detail = {name: props[name] for name in SESSION_PROPERTIES}
    mismatched = _mismatches(detail, user_name, allow_list)
    if mismatched:
        return _not_sure(session_id, detail, mismatched)
    return SessionCheck(
        verdict=Verdict.DESKTOP,
        session_id=session_id,
        scope=detail["Scope"] or None,
        display=None,
        xorg_pid=None,
        xauthority=None,
        detail=MappingProxyType(detail),
    )


def _mismatches(
    detail: Mapping[str, str], user_name: str, allow_list: SessionAllowList
) -> tuple[str, ...]:
    """Names of the allow-listed properties whose value is not allowed."""
    allowed: dict[str, frozenset[str]] = {
        "Name": frozenset({user_name}),
        "Seat": frozenset({allow_list.seat}),
        "Class": frozenset({allow_list.session_class}),
        "Desktop": allow_list.desktop,
        "Type": allow_list.session_type,
    }
    allowed |= {name: frozenset({value}) for name, value in LOGIND_IN_FRONT.items()}
    return tuple(
        name
        for name in SESSION_PROPERTIES
        if name in allowed and detail[name] not in allowed[name]
    )


@dataclass(frozen=True, slots=True)
class _Queries:
    """``loginctl`` queries of one check, within its ``deadline`` (or none)."""

    ctx: "Context"
    deadline: float | None

    def run(
        self, verb: str, name: str, props: tuple[str, ...]
    ) -> dict[str, str] | CommandResult | None:
        """``loginctl <verb> <name> -p <props>`` parsed; the result when it
        failed; None when the deadline left no time to ask."""
        timeout = QUERY_TIMEOUT
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - self.ctx.clock.monotonic())
            if timeout <= 0:
                return None
        argv = (self.ctx.platform.tools.loginctl, verb, name, "-p", ",".join(props))
        result = self.ctx.runner.run(Command(argv=argv, timeout=timeout))
        if result.returncode != 0:
            return result
        return parse_props(result.text())


def _verdict(
    verdict: Verdict, session_id: str | None, detail: dict[str, str]
) -> SessionCheck:
    return SessionCheck(
        verdict=verdict,
        session_id=session_id,
        scope=None,
        display=None,
        xorg_pid=None,
        xauthority=None,
        detail=MappingProxyType(detail),
    )


def _not_sure(
    session_id: str | None, detail: dict[str, str], mismatched: tuple[str, ...]
) -> SessionCheck:
    values = ", ".join(f"{name}={value!r}" for name, value in detail.items())
    log.log(
        NOTICE,
        "%s: %s did not match; %s",
        NOT_RECOGNIZED,
        ", ".join(mismatched),
        values,
    )
    return _verdict(Verdict.NOT_SURE, session_id, detail)


def _unanswered(
    result: CommandResult | None, session_id: str | None, verb: str
) -> SessionCheck:
    """``NOT_SURE`` for a query that failed, or that the deadline left unasked."""
    if result is not None:
        return _failed(result, session_id)
    log.log(NOTICE, "%s: no time left for loginctl %s", NOT_RECOGNIZED, verb)
    return _verdict(Verdict.NOT_SURE, session_id, {})


def _failed(result: CommandResult, session_id: str | None) -> SessionCheck:
    command = " ".join(result.argv[1:3])
    log.log(
        NOTICE,
        "%s: loginctl %s failed: exit %s, timed out %s, not found %s: %s",
        NOT_RECOGNIZED,
        command,
        result.returncode,
        result.timed_out,
        result.not_found,
        result.err_text().strip(),
    )
    return _verdict(Verdict.NOT_SURE, session_id, {})
