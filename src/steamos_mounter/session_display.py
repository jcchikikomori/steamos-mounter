"""The display half of the session check: the user manager's DISPLAY and its X server.

Design Doc "Key Dialog Unit" (session check steps 4 and 5), ADR-0005 D2.2,
DD-20 and "Logging and Secret Handling" (user-session environment). Split out
of ``session`` by step, like ``reconcile_mount``; ``session`` re-exports the
public names and decides the verdict.

- ``parse_display``: from ``systemctl --user show-environment`` output only a
  ``DISPLAY=:<n>`` line is kept; every other line is dropped unread, and the
  command runs with ``log_output=False`` (``show_environment``).
- ``x_listener_pid``, without ``ss`` or ``lsof``: the ``/proc/net/unix`` row
  whose path is exactly ``/tmp/.X11-unix/X<n>`` (never the ``@`` abstract
  one), flags ``00010000`` and state ``01`` gives an inode; the process with a
  ``/proc/<pid>/fd`` link ``socket:[<inode>]`` is the listener. More than one
  such row or holder is doubt, so None.
- ``pid_in_scope``: the cgroup v2 line of ``/proc/<pid>/cgroup`` ends with
  ``/<Scope>``.
- ``x_server_auth``: the X server's ``-auth`` argument, read only when the
  platform's ``xauthority_from_xserver`` flag asks for it (DD-20).

Every ``/proc`` path goes through ``HostPaths.p``, so tests run this code
against real files under ``tmp_path``.
"""

import itertools
import logging
import os
import re
from typing import TYPE_CHECKING, Final

from steamos_mounter.platforms.base import SessionUser
from steamos_mounter.runner import Command

if TYPE_CHECKING:
    from steamos_mounter.context import Context

DISPLAY_LINE: Final = "DISPLAY="
# ":<n>" only: no host, no screen, no leading zero (":00" would name X0).
DISPLAY_VALUE: Final = re.compile(r":(0|[1-9][0-9]{0,4})")
PROC: Final = "/proc"
PROC_NET_UNIX: Final = "/proc/net/unix"
X_SOCKET: Final = "/tmp/.X11-unix/X{number}"  # noqa: S108 - the X socket path
LISTENING_FLAGS: Final = "00010000"  # __SO_ACCEPTCON
LISTENING_STATE: Final = "01"  # SS_UNCONNECTED, as a listening socket shows
SOCKET_LINK: Final = "socket:[{inode}]"
UNIFIED_CGROUP: Final = "0::"  # the cgroup v2 line of /proc/<pid>/cgroup
AUTH_OPTION: Final = "-auth"
TEXT_ERRORS: Final = "surrogateescape"
# Columns of a /proc/net/unix row: Num RefCount Protocol Flags Type St Inode Path.
_UNIX_COLUMNS: Final = 8
_FLAGS: Final = 3
_STATE: Final = 5
_INODE: Final = 6
_PATH: Final = 7

log = logging.getLogger(__name__)


def user_manager_env(user: SessionUser) -> dict[str, str]:
    """The two variables a command needs to reach ``user``'s own manager."""
    return {
        "XDG_RUNTIME_DIR": user.runtime_dir,
        "DBUS_SESSION_BUS_ADDRESS": user.bus_address,
    }


def show_environment(ctx: "Context", timeout: float) -> Command:
    """``systemctl --user show-environment`` as the session user, output unlogged."""
    user = ctx.platform.session_user()
    return Command(
        argv=(ctx.platform.tools.systemctl, "--user", "show-environment"),
        timeout=timeout,
        env_extra=user_manager_env(user),
        user=user.uid,
        group=user.gid,
        log_output=False,
    )


def parse_display(text: str) -> str | None:
    """The ``DISPLAY=:<n>`` value of ``show-environment`` output, or None."""
    for line in text.splitlines():
        if line.startswith(DISPLAY_LINE):
            value = line[len(DISPLAY_LINE) :]
            return value if DISPLAY_VALUE.fullmatch(value) else None
    return None


def x_listener_pid(ctx: "Context", display_number: int) -> int | None:
    """The pid of the one process listening on ``/tmp/.X11-unix/X<n>``, or None.

    None when no row (or more than one) listens on exactly that path, or when
    no process (or more than one) holds the socket.
    """
    path = X_SOCKET.format(number=display_number)
    inodes = _listening_inodes(ctx, path)
    if len(inodes) != 1:
        log.debug("%s: %d listening sockets", path, len(inodes))
        return None
    pids = _socket_holders(ctx, inodes[0])
    if len(pids) != 1:
        log.debug("%s: inode %s held by %d processes", path, inodes[0], len(pids))
        return None
    return pids[0]


def pid_in_scope(ctx: "Context", pid: int, scope: str) -> bool:
    """True when ``pid``'s cgroup v2 path ends with ``/<scope>``."""
    if not scope or "/" in scope:
        return False
    cgroup = cgroup_path(ctx, pid)
    return cgroup is not None and cgroup.endswith(f"/{scope}")


def cgroup_path(ctx: "Context", pid: int) -> str | None:
    """The cgroup v2 path of ``pid`` (its ``0::`` line), or None."""
    data = _read_bytes(ctx, f"{PROC}/{pid}/cgroup")
    if data is None:
        return None
    for line in data.decode("utf-8", TEXT_ERRORS).splitlines():
        if line.startswith(UNIFIED_CGROUP):
            return line[len(UNIFIED_CGROUP) :]
    return None


def x_server_auth(ctx: "Context", pid: int) -> str | None:
    """The absolute path after ``-auth`` in ``pid``'s command line, or None."""
    data = _read_bytes(ctx, f"{PROC}/{pid}/cmdline")
    if data is None:
        return None
    arguments = [os.fsdecode(item) for item in data.split(b"\0")]
    for option, value in itertools.pairwise(arguments):
        if option == AUTH_OPTION:
            return value if os.path.isabs(value) else None
    return None


def _listening_inodes(ctx: "Context", path: str) -> list[str]:
    """Inodes of the listening rows bound to exactly ``path``."""
    data = _read_bytes(ctx, PROC_NET_UNIX)
    if data is None:
        return []
    inodes = []
    for line in data.decode("utf-8", TEXT_ERRORS).splitlines()[1:]:
        columns = line.split(maxsplit=_UNIX_COLUMNS - 1)
        if (
            len(columns) == _UNIX_COLUMNS
            and columns[_PATH] == path
            and columns[_FLAGS] == LISTENING_FLAGS
            and columns[_STATE] == LISTENING_STATE
        ):
            inodes.append(columns[_INODE])
    return inodes


def _socket_holders(ctx: "Context", inode: str) -> list[int]:
    """Pids with a ``/proc/<pid>/fd`` link to ``socket:[<inode>]``, ascending."""
    link = SOCKET_LINK.format(inode=inode)
    try:
        with os.scandir(ctx.paths.p(PROC)) as entries:
            names = [entry.name for entry in entries]
    except OSError as error:
        log.debug("cannot list %s: %s", PROC, error)
        return []
    pids = sorted(int(name) for name in names if name.isdigit())
    return [pid for pid in pids if link in _fd_links(ctx, pid)]


def _fd_links(ctx: "Context", pid: int) -> set[str]:
    """Targets of ``/proc/<pid>/fd/*``; empty for a process that is gone or hidden."""
    try:
        with os.scandir(ctx.paths.p(f"{PROC}/{pid}/fd")) as entries:
            paths = [entry.path for entry in entries]
    except OSError:
        return set()
    targets = set()
    for path in paths:
        try:
            targets.add(os.readlink(path))
        except OSError:
            continue
    return targets


def _read_bytes(ctx: "Context", absolute: str) -> bytes | None:
    try:
        return ctx.paths.p(absolute).read_bytes()
    except OSError as error:
        log.debug("cannot read %s: %s", absolute, error)
        return None
