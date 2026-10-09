"""The platform seam: what every platform provides, and the host path root.

Design Doc "model, context, platforms" and "Platform Seam" (FR-17, NFR-24).
Code outside ``platforms/`` reads distribution facts (tool paths, the mount
base, the session allow-list, the OS partition sources) only through a
``Platform``, and every host path through ``HostPaths.p``, so tests can run
the real logic against files under ``tmp_path``.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from steamos_mounter.context import Context


@dataclass(frozen=True, slots=True)
class HostPaths:
    root: Path = Path("/")

    def p(self, absolute: str) -> Path:
        """``absolute`` placed under ``root`` (the real path when root is ``/``)."""
        return self.root / absolute.lstrip("/")


@dataclass(frozen=True, slots=True)
class SessionUser:
    name: str
    uid: int
    gid: int
    runtime_dir: str
    bus_address: str


@dataclass(frozen=True, slots=True)
class SessionAllowList:
    """Which logind session may get a dialog or a notification."""

    seat: str
    session_class: str
    desktop: frozenset[str]
    session_type: frozenset[str]


@dataclass(frozen=True, slots=True)
class Tools:
    """Absolute paths of every external command the tool runs."""

    mount: str
    umount: str
    findmnt: str
    lsblk: str
    cryptsetup: str
    dmsetup: str
    ntfs3g: str
    ntfs3g_probe: str
    systemctl: str
    systemd_run: str
    udevadm: str
    loginctl: str
    kdialog: str
    zenity: str
    notify_send: str
    rsync: str
    setfacl: str


@dataclass(frozen=True, slots=True)
class OsPartitionSet:
    """The partitions the OS owns (DD-02).

    ``known`` is False when no source yielded an entry; callers then fail
    closed (no auto-mount, no ``add``). ``sources`` names the sources that
    yielded at least one entry, in reading order.
    """

    known: bool
    knames: frozenset[str]
    partuuids: frozenset[str]
    sources: tuple[str, ...]

    def contains(self, kname: str, partuuid: str | None) -> bool:
        """True when ``kname`` is linked or ``partuuid`` is listed (any case)."""
        if kname in self.knames:
            return True
        return partuuid is not None and partuuid.lower() in self.partuuids


class Platform(Protocol):
    name: str
    tools: Tools
    mount_base: str
    # Owner of every trusted file: 0 on the Deck, the test user's uid in tests.
    trusted_uid: int
    auto_fstypes: frozenset[str]
    registrable_fstypes: frozenset[str]
    keep_list: str
    dropin_dir: str
    allow_list: SessionAllowList
    xauthority_from_xserver: bool  # DD-20
    dialog_tool: str
    cli_root: str  # the command prefix printed in next-step hints

    def detect(self, paths: HostPaths) -> bool: ...
    def session_user(self) -> SessionUser: ...
    def os_partitions(self, ctx: "Context", *, as_root: bool) -> OsPartitionSet: ...
    def automount_lock_path(self, kname: str) -> str | None: ...
