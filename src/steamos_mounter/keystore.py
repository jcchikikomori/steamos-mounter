"""The BitLocker key store: key input, the permission check, storage, removal.

Design Doc "Key Store", "Module Responsibilities > keystore", DD-18 and IP-20;
ADR-0004 D4. Keys live only in ``/var/lib/steamos-mounter/keys/`` (root 0700)
as ``<container UUID>.key`` (root 0600), never under ``/etc``.

- **Input**: a hidden prompt (``getpass`` on the terminal), a file, or stdin;
  never argv. File and stdin input lose exactly one trailing ``\\r\\n`` or
  ``\\n``. Empty input, a NUL byte or more than ``KEY_CAP_CLI`` bytes is a
  ``UsageError`` with one generic message; no message carries the input.
  Without a terminal ``getpass`` would warn and read stdin with echo on, so
  that warning is turned into a ``UsageError`` before anything is read.
  Recovery-key formatting is passed as typed (V-02 decides normalisation).
- **Memory**: input is read into one ``bytearray``, wrapped in ``SecretBytes``
  at once, and the buffer is zeroed in ``finally``. The ``str`` that
  ``getpass`` returns cannot be cleared (a Python limit, accepted in the
  Design Doc's Security Considerations).
- **Use**: callers check ``status`` before a stored key is used. Any doubt
  about the directory or the file is ``BAD_PERMISSIONS``: the volume goes to
  ``NeedsKey`` with reason ``key_permissions`` and the owner is pointed to
  ``doctor`` (DD-18). This module never reads a stored key back.
- **Removal** unlinks without an overwrite (ADR-0004 D4.7).
"""

import getpass
import logging
import os
import warnings
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Final, Literal

from steamos_mounter.atomicfile import check_owner_mode, write_atomic
from steamos_mounter.config import UUID_FORMS
from steamos_mounter.errors import MounterError, UsageError
from steamos_mounter.sensitive import SecretBytes

if TYPE_CHECKING:
    from steamos_mounter.context import Context

KEY_CAP_CLI: Final = 1024
KEYS_DIR: Final = "/var/lib/steamos-mounter/keys"
KEY_SUFFIX: Final = ".key"
KEY_MODE: Final = 0o600
FORBIDDEN_BITS: Final = 0o077  # no group or other bits on the directory or a key

NO_TERMINAL: Final = (
    "no terminal for the hidden key prompt. Use --key-file PATH or --key-stdin"
)
INVALID_KEY: Final = f"the key must be 1 to {KEY_CAP_CLI} bytes with no NUL byte"
UNREADABLE_FILE: Final = "cannot read the key file"
UNREADABLE_STDIN: Final = "cannot read the key from stdin"

_CRLF: Final = b"\r\n"
_LF: Final = b"\n"
# A key one byte over the cap behind the longest line ending is still caught.
_READ_LIMIT: Final = KEY_CAP_CLI + len(_CRLF) + 1
_TEXT_ERRORS: Final = "surrogateescape"
_NUL: Final = 0

log = logging.getLogger(__name__)


class KeyStatus(StrEnum):
    OK = "ok"
    MISSING = "missing"
    BAD_PERMISSIONS = "bad-permissions"


def key_path(ctx: "Context", uuid: str) -> Path:
    """The key file of container ``uuid``; ``ValueError`` for a non-registry UUID."""
    if not any(form.fullmatch(uuid) for form in UUID_FORMS):
        raise ValueError(f"not a registry UUID: {uuid!r}")
    return ctx.paths.p(_logical_path(uuid))


def read_key_input(
    *,
    source: Literal["prompt", "file", "stdin"],
    prompt_text: str,
    file_path: str | None,
    stdin: BinaryIO,
    tty_prompt: Callable[[str], str],
) -> SecretBytes:
    """The key from ``source``, checked and wrapped; ``UsageError`` on bad input."""
    if source == "prompt":
        raw = _prompt(prompt_text, tty_prompt)
    elif source == "file":
        if file_path is None:
            raise ValueError("key source 'file' needs a file_path")
        raw = _read_file(file_path)
    elif source == "stdin":
        raw = _read_stdin(stdin)
    else:
        raise ValueError(f"unknown key source {source!r}")
    try:
        if source != "prompt":
            _strip_in_place(raw)
        secret = SecretBytes(raw)
        problem = _input_problem(raw)
        if problem is not None:
            secret.clear()
            raise UsageError(INVALID_KEY, detail=f"key input: {problem}")
        return secret
    finally:
        raw[:] = bytes(len(raw))


def strip_one_line_ending(data: bytes) -> bytes:
    """``data`` without one trailing ``\\r\\n`` or ``\\n``."""
    return data[: len(data) - _ending_length(data)]


def status(ctx: "Context", uuid: str) -> KeyStatus:
    """Whether the stored key of ``uuid`` may be used (DD-18).

    The directory must be a real directory and the file a regular file, both
    owned by ``trusted_uid`` with no group or other bits, the file 1 to
    ``KEY_CAP_CLI`` bytes. Both are examined with ``lstat``: a symlink is never
    followed. A missing directory is an install problem, so it is
    ``BAD_PERMISSIONS``; a missing file in a good directory is ``MISSING``.
    """
    path = key_path(ctx, uuid)
    trusted = ctx.platform.trusted_uid
    where = KEYS_DIR
    problem = check_owner_mode(
        path.parent, uid=trusted, forbid=FORBIDDEN_BITS, kind="dir"
    )
    if problem is None:
        where = _logical_path(uuid)
        try:
            size = os.lstat(path).st_size
        except FileNotFoundError:
            return KeyStatus.MISSING
        problem = check_owner_mode(
            path, uid=trusted, forbid=FORBIDDEN_BITS, kind="file"
        )
        if problem is None and not 1 <= size <= KEY_CAP_CLI:
            log.warning(
                "key file not trusted: %s: size %d is not 1 to %d",
                where,
                size,
                KEY_CAP_CLI,
            )
            return KeyStatus.BAD_PERMISSIONS
    if problem is not None:
        log.warning("key file not trusted: %s: %s", where, problem.problem)
        return KeyStatus.BAD_PERMISSIONS
    return KeyStatus.OK


def store(ctx: "Context", uuid: str, key: SecretBytes) -> None:
    """Write ``key`` as ``<uuid>.key``, root 0600, replacing any old key in one step.

    The directory is checked first and never created here (the installer
    owns it); an untrusted one raises ``MounterError`` pointing to ``doctor``.
    The caller keeps ``key`` and clears it.
    """
    path = key_path(ctx, uuid)
    if not 1 <= len(key) <= KEY_CAP_CLI:
        raise ValueError(f"a stored key is 1 to {KEY_CAP_CLI} bytes, not {len(key)}")
    trusted = ctx.platform.trusted_uid
    problem = check_owner_mode(
        path.parent, uid=trusted, forbid=FORBIDDEN_BITS, kind="dir"
    )
    if problem is not None:
        raise MounterError(
            f"the key store cannot be trusted. Run {ctx.platform.cli_root} doctor",
            detail=f"{KEYS_DIR}: {problem.problem}",
        )
    write_atomic(
        path,
        key.reveal(),
        mode=KEY_MODE,
        uid=trusted,
        # Root entries run with group 0, which gives the Design Doc's
        # root:root; the group carries no trust (mode 0600).
        gid=os.getegid(),
    )
    log.info("key stored for %s", uuid)


def delete(ctx: "Context", uuid: str) -> bool:
    """Unlink the key of ``uuid`` without an overwrite; False when there was none."""
    try:
        os.unlink(key_path(ctx, uuid))
    except FileNotFoundError:
        return False
    log.info("key deleted for %s", uuid)
    return True


def _logical_path(uuid: str) -> str:
    return f"{KEYS_DIR}/{uuid}{KEY_SUFFIX}"


def _prompt(prompt_text: str, tty_prompt: Callable[[str], str]) -> bytearray:
    """The typed text as UTF-8 bytes; the exception that failed is not kept.

    A decode or encode error object holds the typed bytes, so the
    ``UsageError`` is raised outside the ``except`` block, with no context.
    """
    failure: str | None = None
    detail = ""
    with warnings.catch_warnings():
        # getpass without a terminal warns, then reads stdin with echo on.
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            raw = bytearray(tty_prompt(prompt_text), "utf-8", _TEXT_ERRORS)
        except UnicodeError:
            failure, detail = INVALID_KEY, "key input: not valid text"
        except (OSError, EOFError, getpass.GetPassWarning) as error:
            failure, detail = NO_TERMINAL, f"key prompt: {type(error).__name__}"
    if failure is not None:
        raise UsageError(failure, detail=detail)
    return raw


def _read_file(file_path: str) -> bytearray:
    try:
        with open(file_path, "rb") as stream:
            return _read_capped(stream)
    except OSError as error:
        reason = error.strerror
    raise UsageError(UNREADABLE_FILE, detail=f"{file_path}: {reason}")


def _read_stdin(stdin: BinaryIO) -> bytearray:
    try:
        return _read_capped(stdin)
    except OSError as error:
        reason = error.strerror
    raise UsageError(UNREADABLE_STDIN, detail=f"stdin: {reason}")


def _read_capped(stream: BinaryIO) -> bytearray:
    """Up to ``_READ_LIMIT`` bytes into one buffer, zeroed if reading fails."""
    buffer = bytearray(_READ_LIMIT)
    filled = 0
    try:
        while filled < _READ_LIMIT:
            chunk = stream.read(_READ_LIMIT - filled)
            if not chunk:
                break
            buffer[filled : filled + len(chunk)] = chunk
            filled += len(chunk)
    except BaseException:
        buffer[:] = bytes(_READ_LIMIT)
        raise
    del buffer[filled:]
    return buffer


def _ending_length(data: bytes | bytearray) -> int:
    if data.endswith(_CRLF):
        return len(_CRLF)
    if data.endswith(_LF):
        return len(_LF)
    return 0


def _strip_in_place(raw: bytearray) -> None:
    ending = _ending_length(raw)
    if ending:
        raw[-ending:] = bytes(ending)
        del raw[-ending:]


def _input_problem(raw: bytearray) -> str | None:
    if not raw:
        return "empty"
    if _NUL in raw:
        return "contains a NUL byte"
    if len(raw) > KEY_CAP_CLI:
        return f"longer than {KEY_CAP_CLI} bytes"
    return None
