"""One way to write a file, one way to flip a symlink, one owner/mode check.

Design Doc "Registry > Atomic Write" and "Module Responsibilities > atomicfile";
ADR-0004 D3 item 4 and its implementation guidance. The registry, key files,
runtime records, the drop-in and the ``current`` release link all go through
here, so a reader never sees a half-written file or a file with the wrong
mode: the temporary file gets its final mode and owner before any data is
written, is flushed, and is renamed over the target in one step; then the
directory is flushed so the rename survives a power cut.
"""

import contextlib
import os
import secrets
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

TEMP_NAME_BYTES: Final = 8
TEMP_NAME_ATTEMPTS: Final = 100


@dataclass(frozen=True, slots=True)
class OwnerModeProblem:
    """Why ``path`` cannot be trusted, in words for ``doctor`` and the journal."""

    path: str
    problem: str


def write_atomic(path: Path, data: bytes, *, mode: int, uid: int, gid: int) -> None:
    """Replace ``path`` with ``data``, owned ``uid:gid`` with ``mode``.

    ``mkstemp`` in the parent -> ``fchmod`` -> ``fchown`` -> write ->
    ``fsync`` -> close -> ``os.replace`` -> ``fsync`` of the directory. The
    temporary file is unlinked on any error, and the error propagates.
    """
    fd, temporary = _make_temporary(path)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        _unlink_quietly(temporary)
        raise
    _fsync_directory(path.parent)


def replace_symlink(link: Path, target: str) -> None:
    """Point ``link`` at ``target`` with one rename (the release flip, D11).

    A new symlink is made under a random hidden name next to ``link`` and
    renamed over it, so ``link`` always resolves to the old or the new target.
    """
    temporary = _make_temporary_symlink(link, target)
    try:
        os.replace(temporary, link)
    except BaseException:
        _unlink_quietly(temporary)
        raise
    _fsync_directory(link.parent)


def check_owner_mode(
    path: Path, *, uid: int, forbid: int, kind: Literal["file", "dir"]
) -> OwnerModeProblem | None:
    """``None`` when ``path`` is a real ``kind``, owned by ``uid``, no ``forbid`` bits.

    The path itself is examined with ``lstat``, so a symlink is a problem,
    never followed. A missing path is a problem too; callers that allow one
    check for it first.
    """
    try:
        status = os.lstat(path)
    except FileNotFoundError:
        return OwnerModeProblem(str(path), "is missing")
    except OSError as error:
        return OwnerModeProblem(str(path), f"cannot be inspected: {error.strerror}")
    problem = _type_problem(status.st_mode, kind) or _owner_mode_problem(
        status, uid=uid, forbid=forbid
    )
    return None if problem is None else OwnerModeProblem(str(path), problem)


def _type_problem(mode: int, kind: Literal["file", "dir"]) -> str | None:
    if stat.S_ISLNK(mode):
        return "is a symlink"
    if kind == "dir" and not stat.S_ISDIR(mode):
        return "is not a directory"
    if kind == "file" and not stat.S_ISREG(mode):
        return "is not a regular file"
    return None


def _owner_mode_problem(status: os.stat_result, *, uid: int, forbid: int) -> str | None:
    if status.st_uid != uid:
        return f"owned by uid {status.st_uid}, not {uid}"
    permissions = stat.S_IMODE(status.st_mode)
    if permissions & forbid:
        return f"mode {permissions:#o} has forbidden bits {permissions & forbid:#o}"
    return None


def _make_temporary(path: Path) -> tuple[int, str]:
    return tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")


def _make_temporary_symlink(link: Path, target: str) -> Path:
    for _ in range(TEMP_NAME_ATTEMPTS):
        candidate = link.parent / f".{link.name}.{secrets.token_hex(TEMP_NAME_BYTES)}"
        try:
            os.symlink(target, candidate)
        except FileExistsError:
            continue
        return candidate
    raise FileExistsError(f"no free temporary name next to {link}")


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _unlink_quietly(path: str | Path) -> None:
    """Remove a temporary file; one that is already gone is fine."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
