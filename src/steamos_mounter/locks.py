"""The four locks: per volume, registry writer, dialog, and holo's per device.

Design Doc "Locks". Every lock is ``fcntl.flock`` on a file opened
``O_RDWR | O_CREAT | O_CLOEXEC`` (plus ``O_NOFOLLOW``) with mode 0600. Ours
live in the 0700 ``/run/steamos-mounter/locks/`` directory that
``records.ensure_runtime_dirs`` creates on every root entry (D002); holo's is
``/var/run/jupiter-automount-<kname>.lock``, opened the same way holo's
``exec 9<>`` opens it. A lock is released by closing its descriptor; lock
files are never deleted, because deleting one while another process waits on
it would let two holders in.

Waiting polls a non-blocking ``flock`` until the timeout in real seconds,
since the other holder is another process. A timeout raises ``LockTimeout``.

Lock order, when two are held: registry, then volume. Reconcile never takes
the dialog lock, and no component waits on a human while it holds a volume
lock (ADR-0005 D1.6), so no cycle exists.
"""

import fcntl
import logging
import os
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Final

from steamos_mounter.errors import MounterError

if TYPE_CHECKING:
    from steamos_mounter.context import Context

LOCKS_DIR: Final = "/run/steamos-mounter/locks"
REGISTRY_LOCK: Final = f"{LOCKS_DIR}/registry.lock"
DIALOG_LOCK: Final = f"{LOCKS_DIR}/dialog.lock"
VOLUME_LOCK: Final = LOCKS_DIR + "/volume-{key}.lock"
LOCK_FILE_MODE: Final = 0o600
LOCK_OPEN_FLAGS: Final = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
# A lowercased UUID or a "<kname>-<major>_<minor>" record key (I007).
VOLUME_KEY: Final = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}")
POLL_SECONDS: Final = 0.05
REGISTRY_WAIT: Final = 10.0
AUTOMOUNT_WAIT: Final = 5.0

log = logging.getLogger(__name__)


# The Design Doc fixes this public name, so it keeps no Error suffix.
class LockTimeout(MounterError):  # noqa: N818
    """Another holder kept the lock past the timeout."""


@contextmanager
def volume_lock(ctx: "Context", key: str, *, timeout: float) -> Iterator[None]:
    """Hold ``locks/volume-<key lowercased>.lock``.

    ``key`` is the lock key of the Design Doc's I007 table: the registry or
    filesystem UUID, or ``<kname>-<major>_<minor>`` when there is none.
    Raises ``ValueError`` for a key that is not a safe file name.
    """
    lowered = key.lower()
    if VOLUME_KEY.fullmatch(lowered) is None:
        raise ValueError(f"not a lock key: {key!r}")
    with _held(ctx, VOLUME_LOCK.format(key=lowered), timeout):
        yield


@contextmanager
def registry_lock(ctx: "Context", *, timeout: float = REGISTRY_WAIT) -> Iterator[None]:
    """Hold the registry writer lock (``add``, ``remove``, installer restore)."""
    with _held(ctx, REGISTRY_LOCK, timeout):
        yield


@contextmanager
def dialog_lock(ctx: "Context", *, timeout: float) -> Iterator[None]:
    """Hold the dialog lock (key unit, from the dialog to the save question)."""
    with _held(ctx, DIALOG_LOCK, timeout):
        yield


@contextmanager
def automount_lock(
    ctx: "Context", kname: str, *, timeout: float = AUTOMOUNT_WAIT
) -> Iterator[bool]:
    """Hold holo's per-device lock around a mount; yields ``False`` when skipped.

    Skipped when the platform has no lock path for ``kname`` (holo's own
    ``^[a-z0-9]+$``, so never ``dm-*``) or when the lock file cannot be
    opened because ``/var/run`` is not usable (ADR-0002: optional when
    absent). For a mapping, the caller passes the backing partition's kname.
    Raises ``LockTimeout`` when holo holds it past ``timeout``; the caller
    records ``MountFailed`` reason ``device_busy``.
    """
    relative = ctx.platform.automount_lock_path(kname)
    if relative is None:
        yield False
        return
    try:
        fd = _open(ctx.paths.p(relative))
    except OSError as error:
        log.debug("holo lock %s skipped: %s", relative, error.strerror)
        yield False
        return
    _wait(fd, relative, timeout)
    try:
        yield True
    finally:
        os.close(fd)


@contextmanager
def _held(ctx: "Context", absolute: str, timeout: float) -> Iterator[None]:
    try:
        fd = _open(ctx.paths.p(absolute))
    except OSError as error:
        raise MounterError(
            "could not take a steamos-mounter lock",
            detail=f"cannot open {absolute}: {error.strerror}",
        ) from error
    _wait(fd, absolute, timeout)
    try:
        yield
    finally:
        os.close(fd)


def _open(path: Path) -> int:
    return os.open(path, LOCK_OPEN_FLAGS, LOCK_FILE_MODE)


def _wait(fd: int, absolute: str, timeout: float) -> None:
    """``flock`` ``fd`` within ``timeout`` seconds; on failure close it and raise."""
    deadline = time.monotonic() + max(timeout, 0.0)
    try:
        while not _try_lock(fd):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LockTimeout(
                    "another steamos-mounter operation is still running",
                    detail=f"{absolute} still held after {timeout:g} s",
                )
            time.sleep(min(POLL_SECONDS, remaining))
    except BaseException:
        os.close(fd)
        raise


def _try_lock(fd: int) -> bool:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True
