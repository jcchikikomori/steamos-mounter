"""Is the session user at a Desktop Mode session on this seat, and on which display?

Design Doc "Key Dialog Unit" (session check), "Notifications", IP-14,
ADR-0005 D2, DD-19 and DD-20. ``check`` asks logind three questions through
the runner, all as the caller (``loginctl show-*`` needs no privilege):

1. ``loginctl show-user <user> -p Display``: the user's primary graphical
   session; absent or empty means there is none (``NONE``).
2. ``loginctl show-seat <seat> -p ActiveSession`` must name that session.
3. ``loginctl show-session <id> -p Name -p Seat ...`` (one ``-p`` per
   property: systemd 261's loginctl prints nothing for ``-p Name,Seat``)
   must match the allow-list: the session user's name, the platform's seat,
   class, desktops and session types (``SessionAllowList``), plus logind's own
   "in front of the user" values ``Active=yes``, ``Remote=no`` and
   ``State=active``. ``Display`` is reported, not matched: logind leaves it
   empty for this X11 session.

The key dialog (``need_display=True``) also needs the display, which logind
leaves empty for this X11 session, so it is found through the X server:

4. ``systemctl --user show-environment``, as the session user with
   ``log_output=False``: only a ``DISPLAY=:<n>`` line is kept, every other
   line is dropped unread (``user_manager_display``).
5. The listener check, without ``ss`` or ``lsof``: the ``/proc/net/unix`` row
   whose path is exactly ``/tmp/.X11-unix/X<n>``, flags ``00010000`` and state
   ``01`` gives an inode; the one process holding ``socket:[<inode>]`` in
   ``/proc/<pid>/fd`` is the X server (``x_listener_pid``); its
   ``/proc/<pid>/cgroup`` must end with ``/<Scope>`` from logind
   (``pid_in_scope``). With the platform's ``xauthority_from_xserver`` flag
   (DD-20) the X server's ``-auth`` argument is read as well.

Any doubt (a mismatch, ``Type=wayland`` in v1, an unusable session id, a
failed query, no ``DISPLAY``, no listener or one in another scope such as a
stale ``X1``) is ``NOT_SURE``, and one NOTICE line carries the values (AC-076):
a missed dialog or notification is better than one in the wrong place.

A caller with a time budget passes ``deadline`` (a ``ctx.clock.monotonic()``
time): each query then gets at most what is left of it, and once nothing is
left no query runs and the verdict is ``NOT_SURE``. The reading and parsing of
steps 4 and 5 live in ``session_display`` (split by step); every ``/proc`` read
there goes through ``HostPaths.p``.
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
from steamos_mounter.session_display import (
    cgroup_path,
    parse_display,
    show_environment,
    x_server_auth,
)
from steamos_mounter.session_display import pid_in_scope as pid_in_scope
from steamos_mounter.session_display import x_listener_pid as x_listener_pid
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

SHOW_ENVIRONMENT: Final = "systemctl --user show-environment"
# Detail keys of the display half, next to logind's property names.
DISPLAY_KEY: Final = "DISPLAY"
LISTENER_KEY: Final = "XListener"
XAUTHORITY_KEY: Final = "XAUTHORITY"

log = logging.getLogger(__name__)


class Verdict(StrEnum):
    DESKTOP = "desktop"
    NONE = "none"
    NOT_SURE = "not-sure"


@dataclass(frozen=True, slots=True)
class SessionCheck:
    """What ``check`` found. ``detail`` holds the values it decided on.

    ``display``, ``xorg_pid`` and ``xauthority`` are set only by a
    ``need_display=True`` check that verified them; ``xauthority`` only when
    the platform takes it from the X server (DD-20).
    """

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


def property_flags(props: tuple[str, ...]) -> tuple[str, ...]:
    """``("-p", name)`` for each property, in order.

    loginctl needs one ``-p`` per property: on systemd 261 ``-p Name,Seat``
    exits 0 and prints nothing, which would read as every value empty.
    """
    return tuple(flag for name in props for flag in ("-p", name))


def parse_props(text: str) -> dict[str, str]:
    """``loginctl show-*`` output as a dict; an absent key reads as ``""``.

    loginctl prints properties with systemctl's printer, so the parsing
    (``Name=value`` lines, quoted values unquoted) is ``systemd.parse_show``.
    Values are read by name only: loginctl prints them in its own order, not
    in the order they were asked for.
    The full ``show-session`` omits an empty ``Display`` while ``-p Display``
    prints ``Display=``; both read as ``""`` here, and reading an absent key
    adds nothing to the dict.
    """
    return _Props(parse_show(text))


def check(
    ctx: "Context", *, need_display: bool, deadline: float | None = None
) -> SessionCheck:
    """The session verdict for the platform's session user and seat.

    ``need_display=True`` (the key dialog) adds steps 4 and 5; ``DESKTOP``
    then carries the verified display and X server. With a ``deadline`` no
    query runs past it (``QUERY_TIMEOUT`` at most each).
    """
    queries = _Queries(ctx, deadline)
    found = _logind(ctx, queries)
    if found.verdict is not Verdict.DESKTOP or not need_display:
        return found
    return _display(ctx, queries, found)


def _logind(ctx: "Context", queries: "_Queries") -> SessionCheck:
    """Steps 1 to 3: ``DESKTOP`` when logind's session matches the allow-list."""
    user_name = ctx.platform.session_user().name
    allow_list = ctx.platform.allow_list

    user = queries.run("show-user", user_name, ("Display",))
    if not isinstance(user, dict):
        return _unanswered(user, None, "loginctl show-user")
    session_id = user["Display"]
    if not session_id:
        log.info("%s has no graphical session", user_name)
        return _verdict(Verdict.NONE, None, {"Display": ""})
    if SESSION_ID.fullmatch(session_id) is None:
        return _not_sure(None, {"Display": session_id}, ("Display",))

    seat = queries.run("show-seat", allow_list.seat, ("ActiveSession",))
    if not isinstance(seat, dict):
        return _unanswered(seat, session_id, "loginctl show-seat")
    if seat["ActiveSession"] != session_id:
        detail = {"Display": session_id, "ActiveSession": seat["ActiveSession"]}
        return _not_sure(session_id, detail, ("ActiveSession",))

    props = queries.run("show-session", session_id, SESSION_PROPERTIES)
    if not isinstance(props, dict):
        return _unanswered(props, session_id, "loginctl show-session")
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


def _display(ctx: "Context", queries: "_Queries", logind: SessionCheck) -> SessionCheck:
    """Steps 4 and 5 on top of a logind ``DESKTOP``: the verified X display."""
    session_id = logind.session_id
    detail = dict(logind.detail)
    environment = queries.environment()
    if not isinstance(environment, str):
        return _unanswered(environment, session_id, SHOW_ENVIRONMENT)
    display = parse_display(environment)
    detail[DISPLAY_KEY] = display or ""
    if display is None:
        return _not_sure(session_id, detail, (DISPLAY_KEY,))
    pid = x_listener_pid(ctx, int(display[1:]))
    detail[LISTENER_KEY] = "" if pid is None else str(pid)
    if pid is None or logind.scope is None:
        return _not_sure(session_id, detail, (LISTENER_KEY,))
    if not pid_in_scope(ctx, pid, logind.scope):
        detail[LISTENER_KEY] = f"{pid} in {cgroup_path(ctx, pid) or 'no cgroup'}"
        return _not_sure(session_id, detail, (LISTENER_KEY,))
    xauthority = None
    if ctx.platform.xauthority_from_xserver:
        xauthority = x_server_auth(ctx, pid)
        detail[XAUTHORITY_KEY] = xauthority or ""
        if xauthority is None:
            return _not_sure(session_id, detail, (XAUTHORITY_KEY,))
    return SessionCheck(
        verdict=Verdict.DESKTOP,
        session_id=session_id,
        scope=logind.scope,
        display=display,
        xorg_pid=pid,
        xauthority=xauthority,
        detail=MappingProxyType(detail),
    )


def user_manager_display(ctx: "Context") -> str | None:
    """The session user's manager's ``DISPLAY`` (``":0"``), or None.

    None when the query fails or the value is not ``:<n>``. The rest of that
    environment is never logged (``log_output=False``) and never kept.
    """
    result = ctx.runner.run(show_environment(ctx, QUERY_TIMEOUT))
    if result.returncode != 0:
        log.debug("show-environment failed: exit %s", result.returncode)
        return None
    return parse_display(result.text())


@dataclass(frozen=True, slots=True)
class _Queries:
    """The queries of one check, within its ``deadline`` (or none)."""

    ctx: "Context"
    deadline: float | None

    def timeout(self) -> float | None:
        """``QUERY_TIMEOUT``, cut to what is left; None when nothing is left."""
        if self.deadline is None:
            return QUERY_TIMEOUT
        left = self.deadline - self.ctx.clock.monotonic()
        return min(QUERY_TIMEOUT, left) if left > 0 else None

    def run(
        self, verb: str, name: str, props: tuple[str, ...]
    ) -> dict[str, str] | CommandResult | None:
        """``loginctl <verb> <name> -p <prop> ...`` parsed; the result when
        it failed; None when the deadline left no time to ask."""
        timeout = self.timeout()
        if timeout is None:
            return None
        argv = (self.ctx.platform.tools.loginctl, verb, name, *property_flags(props))
        result = self.ctx.runner.run(Command(argv=argv, timeout=timeout))
        if result.returncode != 0:
            return result
        return parse_props(result.text())

    def environment(self) -> str | CommandResult | None:
        """``show-environment`` output; the result when it failed; None when
        the deadline left no time to ask."""
        timeout = self.timeout()
        if timeout is None:
            return None
        result = self.ctx.runner.run(show_environment(self.ctx, timeout))
        if result.returncode != 0:
            return result
        return result.text()


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
    result: CommandResult | None, session_id: str | None, label: str
) -> SessionCheck:
    """``NOT_SURE`` for a query that failed, or that the deadline left unasked."""
    if result is not None:
        return _failed(result, session_id, label)
    log.log(NOTICE, "%s: no time left for %s", NOT_RECOGNIZED, label)
    return _verdict(Verdict.NOT_SURE, session_id, {})


def _failed(result: CommandResult, session_id: str | None, label: str) -> SessionCheck:
    # show-environment output is the user's environment: never logged, and
    # stderr of a failed query carries none of it.
    log.log(
        NOTICE,
        "%s: %s failed: exit %s, timed out %s, not found %s: %s",
        NOT_RECOGNIZED,
        label,
        result.returncode,
        result.timed_out,
        result.not_found,
        result.err_text().strip(),
    )
    return _verdict(Verdict.NOT_SURE, session_id, {})
