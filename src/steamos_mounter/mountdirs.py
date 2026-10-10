"""The mount base and the mount target directories (AC-024, DD-26, IP-17).

Split out of ``mounter`` to keep it under 500 lines; ``mounter`` re-exports
``ensure_mount_base`` and ``prepare_target``, the names the Design Doc gives.

- The mount base is created only when missing, in the layout udisks makes on
  the Deck: ``/run/media`` root 0755, the base root 0750 plus
  ``setfacl -m u:<uid>:r-x``. A present base is never changed.
- Every mount target, auto or registered, is a direct child of the mount
  base (fixed-path rule 9); any other target is refused before the disk is
  looked at, so no mount point can sit between the base and the leaf.
- The tool creates only the leaf directory (root 0755), never a parent, and
  checks the target again right before every mount, fixed-path rule 8
  included: every directory above the target is a real directory owned by
  the trusted uid (root on the Deck) without group or other write, so no
  other user can swap the leaf for a symlink before ``mount(8)`` follows it.
"""

import logging
import os
import posixpath
import stat
import unicodedata
from typing import TYPE_CHECKING, Final

from steamos_mounter.atomicfile import check_owner_mode
from steamos_mounter.errors import MounterError, RefusedError, ToolError
from steamos_mounter.naming import (
    NOT_BASE_CHILD,
    UNTRUSTED_PARENT,
    PathKind,
    has_trusted_parents,
    is_base_child,
)
from steamos_mounter.platforms.base import HostPaths
from steamos_mounter.runner import Command

if TYPE_CHECKING:
    from steamos_mounter.context import Context

SETFACL_TIMEOUT: Final = 10.0
MOUNT_BASE_PARENT_MODE: Final = 0o755
MOUNT_BASE_MODE: Final = 0o750
LEAF_MODE: Final = 0o755
MOUNT_BASE_FAILED: Final = "cannot set up the mount base"
LEAF_FAILED: Final = "cannot create the mount directory"
# Rule 8: a trusted directory has neither group nor other write permission.
# With an ACL the group bits show the ACL mask, so a named-user write entry
# shows up here too.
UNTRUSTED_WRITE_BITS: Final = stat.S_IWGRP | stat.S_IWOTH
_NO_FOLLOW_DIR: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_DIRECTORIES: Final = frozenset({PathKind.EMPTY_DIR, PathKind.NON_EMPTY_DIR})

log = logging.getLogger(__name__)


def ensure_mount_base(ctx: "Context") -> None:
    """Create ``/run/media`` and the mount base with its ACL when missing.

    When the ACL cannot be set the new base is removed again, so the next
    attempt recreates it whole. Raises ``MounterError`` or ``ToolError``.
    """
    base = ctx.platform.mount_base
    _make_dir(ctx.paths, posixpath.dirname(base), MOUNT_BASE_PARENT_MODE)
    if not _make_dir(ctx.paths, base, MOUNT_BASE_MODE):
        return
    entry = f"u:{ctx.platform.session_user().uid}:r-x"
    argv = (ctx.platform.tools.setfacl, "-m", entry, base)
    result = ctx.runner.run(Command(argv=argv, timeout=SETFACL_TIMEOUT))
    if result.returncode != 0:
        os.rmdir(ctx.paths.p(base))
        why = " ".join(result.err_text().split())
        raise ToolError(
            MOUNT_BASE_FAILED,
            detail=(
                f"setfacl {base}: exit {result.returncode}, timed out "
                f"{result.timed_out}, not found {result.not_found}: {why}"
            ),
        )
    log.info("created the mount base %s with %s", base, entry)


def _make_dir(paths: HostPaths, absolute: str, mode: int) -> bool:
    """True when this call created ``absolute``; an existing one must be a dir."""
    path = paths.p(absolute)
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            raise MounterError(
                MOUNT_BASE_FAILED, detail=f"{absolute}: not a directory"
            ) from None
        return False
    except OSError as error:
        raise MounterError(
            MOUNT_BASE_FAILED, detail=f"{absolute}: {error.strerror}"
        ) from error
    os.chmod(path, mode)  # mkdir applies the umask
    return True


class HostPathFacts:
    """``naming.PathFacts`` on the host tree; a symlink is never a directory.

    ``trusted_uid`` is the owner a trusted directory must have: the
    platform's ``trusted_uid`` (root, or the test user under ``tmp_path``).
    """

    def __init__(self, paths: HostPaths, *, trusted_uid: int) -> None:
        self._paths = paths
        self._trusted_uid = trusted_uid

    def kind(self, path: str) -> PathKind:
        host = self._paths.p(path)
        try:
            mode = os.lstat(host).st_mode
        except (FileNotFoundError, NotADirectoryError):
            return PathKind.MISSING
        if not stat.S_ISDIR(mode):
            return PathKind.OTHER
        with os.scandir(host) as entries:
            return PathKind.NON_EMPTY_DIR if any(entries) else PathKind.EMPTY_DIR

    def trusted_dir(self, path: str) -> bool:
        problem = check_owner_mode(
            self._paths.p(path),
            uid=self._trusted_uid,
            forbid=UNTRUSTED_WRITE_BITS,
            kind="dir",
        )
        return problem is None


def prepare_target(ctx: "Context", target: str) -> bool:
    """Check ``target`` again right before mounting; create only the leaf.

    ``target`` must be a direct child of the mount base (rule 9), an auto or
    a registered name; auto names keep printable Unicode, which the
    fixed-path character rule refuses, so rule 1 is not applied whole here.
    It must be missing or an empty directory under trusted parent directories
    (rules 5, 7 and 8). Returns True when this call created the leaf. Raises
    ``RefusedError`` or ``MounterError``.
    """
    if not is_base_child(target, ctx.platform.mount_base):
        raise _refuse(target, NOT_BASE_CHILD)
    facts = HostPathFacts(ctx.paths, trusted_uid=ctx.platform.trusted_uid)
    _check_base_child(target, facts)
    if facts.kind(target) is PathKind.EMPTY_DIR:
        return False
    _make_leaf(ctx.paths, target)
    return True


def _check_base_child(target: str, facts: HostPathFacts) -> None:
    """The fixed-path rules that also hold for an auto name (rules 1, 5, 7, 8)."""
    kind = facts.kind(target)
    reason = None
    if any(unicodedata.category(char) == "Cc" for char in target):
        reason = "path contains a control character"
    elif posixpath.basename(target) in {"", ".", ".."} or (
        posixpath.normpath(target) != target
    ):
        reason = "path is not normalized"
    elif kind is PathKind.NON_EMPTY_DIR:
        reason = "path is a directory that is not empty"
    elif kind is PathKind.OTHER:
        reason = "path exists and is not a directory"
    elif facts.kind(posixpath.dirname(target)) not in _DIRECTORIES:
        reason = "parent directory does not exist"
    elif not has_trusted_parents(target, facts):
        reason = UNTRUSTED_PARENT
    if reason is not None:
        raise _refuse(target, reason)


def _refuse(target: str, reason: str) -> RefusedError:
    return RefusedError(reason, detail=f"mount target {target!r} refused: {reason}")


def _make_leaf(paths: HostPaths, target: str) -> None:
    """mkdir the leaf through no-follow handles, so a swapped link is refused."""
    try:
        parent = os.open(paths.p(posixpath.dirname(target)), _NO_FOLLOW_DIR)
        try:
            name = posixpath.basename(target)
            os.mkdir(name, LEAF_MODE, dir_fd=parent)
            leaf = os.open(name, _NO_FOLLOW_DIR, dir_fd=parent)
            try:
                os.fchmod(leaf, LEAF_MODE)  # mkdir applies the umask
            finally:
                os.close(leaf)
        finally:
            os.close(parent)
    except OSError as error:
        raise MounterError(LEAF_FAILED, detail=f"{target}: {error.strerror}") from error
