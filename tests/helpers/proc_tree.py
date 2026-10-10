"""Fake ``/proc`` entries under a test root (``HostPaths(root=tmp_path)``).

Design Doc "Mock Boundary Decisions": ``/proc`` is not mocked; the session
check's listener check reads real files and real symlinks under ``tmp_path``:

- ``/proc/net/unix``: the table text, by default the synthetic
  ``proc-net-unix-x0-listening.txt`` (Xorg's ``/tmp/.X11-unix/X0`` listener
  is inode 2205399, the abstract one 2205398, no ``X1`` row);
- ``/proc/<pid>/fd/<n>``: symlinks whose target is the kernel's link text,
  such as ``socket:[2205399]`` (a dangling link, as ``readlink`` sees it);
- ``/proc/<pid>/cgroup`` and ``/proc/<pid>/cmdline`` (NUL-separated).
"""

from collections.abc import Mapping, Sequence
from pathlib import Path

from tests.helpers.fixtures import load_fixture

NET_UNIX_FIXTURE = "proc-net-unix-x0-listening.txt"
XORG_CGROUP_FIXTURE = "proc-cgroup-xorg.txt"
OTHER_SCOPE_CGROUP_FIXTURE = "proc-cgroup-other-scope.txt"
X0_INODE = 2205399
X0_ABSTRACT_INODE = 2205398
XORG_PID = 4242
XORG_FD = 7
XORG_AUTH = "/run/user/1000/xauth_test"
XORG_CMDLINE = (
    "/usr/lib/Xorg",
    "-nolisten",
    "tcp",
    "-background",
    "none",
    "-seat",
    "seat0",
    "vt1",
    "-auth",
    XORG_AUTH,
    "-noreset",
    "-displayfd",
    "16",
)


UNIX_HEADER = "Num       RefCount Protocol Flags    Type St Inode Path"
LISTENING = "00010000"


def socket_link(inode: int) -> str:
    return f"socket:[{inode}]"


def unix_row(
    inode: int, path: str = "", *, flags: str = LISTENING, state: str = "01"
) -> str:
    """One ``/proc/net/unix`` row: a listening stream socket by default."""
    row = f"0000000000000000: 00000002 00000000 {flags} 0001 {state} {inode}"
    return f"{row} {path}" if path else row


def unix_table(*rows: str) -> str:
    return "\n".join((UNIX_HEADER, *rows)) + "\n"


class ProcTree:
    """Builds ``/proc`` entries under ``root``."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def path(self, absolute: str) -> Path:
        """``absolute`` mapped under the root, like ``HostPaths.p``."""
        return self.root / absolute.lstrip("/")

    def net_unix(self, text: str | None = None) -> Path:
        """Write ``/proc/net/unix`` (default: the X0-listening synthetic)."""
        if text is None:
            text = load_fixture(NET_UNIX_FIXTURE).decode("utf-8")
        target = self.path("/proc/net/unix")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def process(
        self,
        pid: int,
        *,
        fds: Mapping[int, str] | None = None,
        cgroup: str | None = None,
        cmdline: Sequence[str] | None = None,
    ) -> Path:
        """``/proc/<pid>`` with an ``fd/`` directory and the given files."""
        directory = self.path(f"/proc/{pid}")
        (directory / "fd").mkdir(parents=True, exist_ok=True)
        for number, target in (fds or {}).items():
            (directory / "fd" / str(number)).symlink_to(target)
        if cgroup is not None:
            (directory / "cgroup").write_text(cgroup, encoding="utf-8")
        if cmdline is not None:
            data = b"".join(item.encode() + b"\0" for item in cmdline)
            (directory / "cmdline").write_bytes(data)
        return directory

    def xorg(
        self,
        *,
        pid: int = XORG_PID,
        cgroup_fixture: str = XORG_CGROUP_FIXTURE,
        cmdline: Sequence[str] = XORG_CMDLINE,
    ) -> Path:
        """The Deck's Desktop Mode X server: X0's listener in session-5.scope."""
        cgroup = load_fixture(cgroup_fixture).decode("utf-8")
        return self.process(
            pid,
            fds={
                0: "/dev/null",
                XORG_FD - 1: socket_link(X0_ABSTRACT_INODE),
                XORG_FD: socket_link(X0_INODE),
            },
            cgroup=cgroup,
            cmdline=cmdline,
        )

    def desktop(self) -> None:
        """``/proc/net/unix`` from the synthetic plus the X server and a client."""
        self.net_unix()
        self.xorg()
        self.process(
            4300,
            fds={3: "socket:[2207110]", 4: "anon_inode:[eventfd]"},
            cgroup="0::/user.slice/user-1000.slice/session-5.scope\n",
        )
