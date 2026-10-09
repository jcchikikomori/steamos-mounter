"""Every SteamOS-specific fact (Design Doc "Platform Seam", FR-17, NFR-24).

The OS partition set (DD-02) is the union of three sources:

1. ``/dev/disk/by-partsets/all/*`` links, resolved to ``/dev/<kname>``;
2. PARTUUIDs in holo's ``/run/udev/rules.d/90-holo-partsets-all.rules``;
3. RFC 4122 tokens of ``/efi/SteamOS/partsets/all``, read only as root
   (``deck`` gets "Permission denied").

``deck`` can read the first two, so ``scan`` and ``list`` explain refusals.
A source that cannot be read adds nothing; when no source yields an entry the
set is unknown and root-side decisions fail closed. holo's own check fails
open when the partsets file is unreadable; that pattern is not copied.
"""

import logging
import os
import pwd
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from steamos_mounter.errors import MounterError
from steamos_mounter.platforms.base import (
    HostPaths,
    OsPartitionSet,
    SessionAllowList,
    SessionUser,
    Tools,
)

if TYPE_CHECKING:
    from steamos_mounter.context import Context

OS_RELEASE: Final = "/etc/os-release"
# The entry point's rule (bin/steamos-mounter): the ID line, quoted or not.
STEAMOS_ID_LINES: Final = frozenset({"ID=steamos", 'ID="steamos"'})
SESSION_USER = "deck"  # resolved with pwd at use time, never cached

PARTSETS_LINKS: Final = "/dev/disk/by-partsets/all"
HOLO_RULES: Final = "/run/udev/rules.d/90-holo-partsets-all.rules"
PARTSETS_FILE: Final = "/efi/SteamOS/partsets/all"
RULE_PARTUUID: Final = re.compile(r'ENV\{ID_PART_ENTRY_UUID\}=="([0-9a-fA-F-]{36})"')
RFC4122: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)

# holo's lock file; the lock is taken only for names holo itself could build.
AUTOMOUNT_LOCK: Final = "/var/run/jupiter-automount-{kname}.lock"
HOLO_KNAME: Final = re.compile(r"[a-z0-9]+")

TOOLS: Final = Tools(
    mount="/usr/bin/mount",
    umount="/usr/bin/umount",
    findmnt="/usr/bin/findmnt",
    lsblk="/usr/bin/lsblk",
    cryptsetup="/usr/bin/cryptsetup",
    dmsetup="/usr/bin/dmsetup",
    ntfs3g="/usr/bin/ntfs-3g",
    ntfs3g_probe="/usr/bin/ntfs-3g.probe",
    systemctl="/usr/bin/systemctl",
    systemd_run="/usr/bin/systemd-run",
    udevadm="/usr/bin/udevadm",
    loginctl="/usr/bin/loginctl",
    kdialog="/usr/bin/kdialog",
    zenity="/usr/bin/zenity",
    notify_send="/usr/bin/notify-send",
    rsync="/usr/bin/rsync",
    setfacl="/usr/bin/setfacl",
)
MOUNT_BASE: Final = "/run/media/deck"
AUTO_FSTYPES: Final = frozenset({"ntfs", "exfat", "vfat", "btrfs"})
REGISTRABLE_FSTYPES: Final = AUTO_FSTYPES | {"BitLocker"}
KEEP_LIST: Final = "/usr/lib/rauc/atomic-update-keep.conf"
DROPIN_DIR: Final = "/etc/atomic-update.conf.d"
ALLOW_LIST: Final = SessionAllowList(
    seat="seat0",
    session_class="user",
    desktop=frozenset({"KDE"}),
    session_type=frozenset({"x11"}),
)
DIALOG_TOOL: Final = "kdialog"  # "zenity" if V-17 fails for kdialog
CLI_ROOT: Final = "sudo /opt/steamos-mounter/bin/steamos-mounter"

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True, kw_only=True)
class SteamOSPlatform:
    name: str = "steamos"
    tools: Tools = TOOLS
    mount_base: str = MOUNT_BASE
    trusted_uid: int = 0
    auto_fstypes: frozenset[str] = AUTO_FSTYPES
    registrable_fstypes: frozenset[str] = REGISTRABLE_FSTYPES
    keep_list: str = KEEP_LIST
    dropin_dir: str = DROPIN_DIR
    allow_list: SessionAllowList = ALLOW_LIST
    xauthority_from_xserver: bool = False  # DD-20; V-21 may flip it
    dialog_tool: str = DIALOG_TOOL
    cli_root: str = CLI_ROOT

    def detect(self, paths: HostPaths) -> bool:
        """True when os-release has ``ID=steamos``; ``ID_LIKE`` does not count."""
        text = _read_text(paths, OS_RELEASE)
        if text is None:
            return False
        return any(line.strip() in STEAMOS_ID_LINES for line in text.splitlines())

    def session_user(self) -> SessionUser:
        try:
            entry = pwd.getpwnam(SESSION_USER)
        except KeyError as error:
            raise MounterError(
                "session user not found",
                detail=f"no passwd entry for {SESSION_USER!r}",
            ) from error
        runtime_dir = f"/run/user/{entry.pw_uid}"
        return SessionUser(
            name=entry.pw_name,
            uid=entry.pw_uid,
            gid=entry.pw_gid,
            runtime_dir=runtime_dir,
            bus_address=f"unix:path={runtime_dir}/bus",
        )

    def os_partitions(self, ctx: "Context", *, as_root: bool) -> OsPartitionSet:
        knames = _linked_knames(ctx.paths)
        rules = _rule_partuuids(ctx.paths)
        partsets = _partsets_partuuids(ctx.paths) if as_root else frozenset()
        yielded = (
            (PARTSETS_LINKS, knames),
            (HOLO_RULES, rules),
            (PARTSETS_FILE, partsets),
        )
        sources = tuple(source for source, entries in yielded if entries)
        return OsPartitionSet(
            known=bool(sources),
            knames=knames,
            partuuids=rules | partsets,
            sources=sources,
        )

    def automount_lock_path(self, kname: str) -> str | None:
        if HOLO_KNAME.fullmatch(kname) is None:
            return None
        return AUTOMOUNT_LOCK.format(kname=kname)


def _read_text(paths: HostPaths, absolute: str) -> str | None:
    """File text, or None (logged) when it cannot be read."""
    try:
        return paths.p(absolute).read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        log.debug("cannot read %s: %s", absolute, error)
        return None


def _linked_knames(paths: HostPaths) -> frozenset[str]:
    """knames the by-partsets links resolve to; links leaving /dev are skipped."""
    try:
        links = list(paths.p(PARTSETS_LINKS).iterdir())
    except OSError as error:
        log.debug("cannot read %s: %s", PARTSETS_LINKS, error)
        return frozenset()
    dev = os.path.realpath(paths.p("/dev"))
    targets = (os.path.realpath(link) for link in links)
    return frozenset(
        os.path.basename(target) for target in targets if os.path.dirname(target) == dev
    )


def _rule_partuuids(paths: HostPaths) -> frozenset[str]:
    text = _read_text(paths, HOLO_RULES)
    if text is None:
        return frozenset()
    return frozenset(match.lower() for match in RULE_PARTUUID.findall(text))


def _partsets_partuuids(paths: HostPaths) -> frozenset[str]:
    text = _read_text(paths, PARTSETS_FILE)
    if text is None:
        return frozenset()
    return frozenset(
        token.lower() for token in text.split() if RFC4122.fullmatch(token)
    )
