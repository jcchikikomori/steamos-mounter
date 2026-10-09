"""BitLocker: unlock, key test, close, and finding mappings on a container.

Design Doc "BitLocker Unlock and Mappings" (the argv table is authoritative),
"Module Responsibilities > bitlocker", DD-15, DD-29, IP-10 and IP-11.

- A key reaches cryptsetup only on stdin (``--key-file=-``) as the caller's
  ``SecretBytes``, or as the path of the 0600 key file; it is never an argv
  item and this module never reads a stored key into Python.
- cryptsetup exit status: 0 opened, 2 rejected key, 5 busy (or the mapping
  already exists); anything else, a timeout or a missing binary is a tool
  failure, logged with the tool's stderr (redacted by the logging setup).
- The tool's own mapping is ``steamos-mounter-<registry UUID>``; a valid UUID
  holds only hex digits and ``-``, so the name is safe in argv. Foreign
  mappings (Dolphin's, named from the label) are addressed by device number
  only (DD-15).
- While a container is present its mapping is found through sysfs
  ``holders/`` and ``dm/name``. At unplug sysfs no longer links the container,
  so stacked mappings are found by asking ``dmsetup deps`` about every
  ``/sys/block/dm-*`` (ADR-0001 guidance 10).
"""

import logging
import os
import re
import time
from collections.abc import Iterable
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Literal

from steamos_mounter import blockdev
from steamos_mounter.blockdev import BlockDevice
from steamos_mounter.config import UUID_FORMS
from steamos_mounter.runner import Command, CommandResult
from steamos_mounter.sensitive import SecretBytes

if TYPE_CHECKING:
    from steamos_mounter.context import Context

MAPPING_PREFIX: Final = "steamos-mounter-"
OPEN_TIMEOUT: Final = 30.0
CLOSE_TIMEOUT: Final = 10.0
DMSETUP_TIMEOUT: Final = 10.0
INNER_READY_TIMEOUT: Final = 5.0  # DD-29
POLL_INTERVAL: Final = 0.25
EXIT_REJECTED: Final = 2
EXIT_BUSY: Final = 5

_BITLK: Final = ("--type", "bitlk")
_KEY_ON_STDIN: Final = "--key-file=-"
_SYS_BLOCK: Final = "/sys/block"
_DM_KNAME: Final = re.compile(r"dm-(\d+)")
_DEVNUM: Final = re.compile(r"(\d+):(\d+)")
_DEPS_LINE: Final = re.compile(r"(\d+) dependencies\s*:(.*)")
_DEPS_PAIR: Final = re.compile(r"\((\d+), (\d+)\)")

log = logging.getLogger(__name__)


class UnlockOutcome(StrEnum):
    OPENED = "opened"
    REJECTED = "rejected"
    FAILED = "failed"


def mapping_name(container_uuid: str) -> str:
    """``steamos-mounter-<UUID>``; ``ValueError`` unless ``container_uuid`` is valid."""
    if not any(form.fullmatch(container_uuid) for form in UUID_FORMS):
        raise ValueError(f"not a registry UUID: {container_uuid!r}")
    return MAPPING_PREFIX + container_uuid


def is_tool_mapping(name: str | None) -> bool:
    """True when a ``dm/name`` is one of this tool's mapping names."""
    return name is not None and name.startswith(MAPPING_PREFIX)


def open_with_file(
    ctx: "Context", device: str, uuid: str, key_path: str
) -> UnlockOutcome:
    """Open ``device`` as the tool mapping with the stored key file (one attempt)."""
    name = mapping_name(uuid)
    argv = (
        ctx.platform.tools.cryptsetup,
        "open",
        *_BITLK,
        "--key-file",
        _absolute(key_path),
        _absolute(device),
        name,
    )
    return _unlock(ctx, Command(argv=argv, timeout=OPEN_TIMEOUT), f"open {name}")


def open_with_secret(
    ctx: "Context", device: str, uuid: str, key: SecretBytes
) -> UnlockOutcome:
    """Open ``device`` as the tool mapping with ``key`` on stdin (one attempt)."""
    name = mapping_name(uuid)
    argv = (
        ctx.platform.tools.cryptsetup,
        "open",
        *_BITLK,
        _KEY_ON_STDIN,
        _absolute(device),
        name,
    )
    command = Command(argv=argv, timeout=OPEN_TIMEOUT, stdin=key)
    return _unlock(ctx, command, f"open {name}")


def test_key(ctx: "Context", device: str, key: SecretBytes) -> UnlockOutcome:
    """Check ``key`` against ``device`` without opening it (FR-16)."""
    argv = (
        ctx.platform.tools.cryptsetup,
        "open",
        "--test-passphrase",
        *_BITLK,
        _KEY_ON_STDIN,
        _absolute(device),
    )
    command = Command(argv=argv, timeout=OPEN_TIMEOUT, stdin=key)
    return _unlock(ctx, command, f"open --test-passphrase {device}")


def close_own(
    ctx: "Context", uuid: str, *, deferred: bool
) -> Literal["closed", "busy", "absent", "failed"]:
    """Close the tool's mapping for ``uuid`` by name (DD-15).

    No mapping of that name in sysfs gives ``absent`` without running
    anything; a failed close whose mapping vanished meanwhile is ``absent``
    too. Exit 5 is ``busy``; with ``deferred`` the kernel removes a busy
    mapping once its last user closes it, and cryptsetup exits 0.
    """
    name = mapping_name(uuid)
    if not _mapping_named(ctx, name):
        return "absent"
    argv = (
        ctx.platform.tools.cryptsetup,
        "close",
        *(("--deferred",) if deferred else ()),
        name,
    )
    result = ctx.runner.run(Command(argv=argv, timeout=CLOSE_TIMEOUT))
    if result.returncode == 0:
        return "closed"
    if result.returncode == EXIT_BUSY:
        log.warning("cryptsetup close %s: busy", name)
        return "busy"
    if not _mapping_named(ctx, name):
        return "absent"
    log.error("cryptsetup close %s failed: %s", name, _describe(result))
    return "failed"


def remove_by_devnum(ctx: "Context", devnum: str) -> Literal["removed", "failed"]:
    """``dmsetup remove --deferred`` a foreign mapping by device number (DD-15)."""
    major, minor = _split_devnum(devnum)
    argv = (
        ctx.platform.tools.dmsetup,
        "remove",
        "--deferred",
        "-j",
        major,
        "-m",
        minor,
    )
    result = ctx.runner.run(Command(argv=argv, timeout=DMSETUP_TIMEOUT))
    if result.returncode == 0:
        return "removed"
    log.error("dmsetup remove %s failed: %s", devnum, _describe(result))
    return "failed"


def mappings_stacked_on(
    ctx: "Context", devnums: Iterable[str]
) -> tuple[tuple[str, str | None], ...]:
    """``(dm devnum, dm name)`` of every mapping that depends on any of ``devnums``.

    One ``dmsetup deps -o devno`` per ``/sys/block/dm-*``, in dm number order.
    The device number is what ``remove_by_devnum`` takes; the name tells the
    tool's own mapping from a foreign one. A mapping that has no ``dev`` any
    more, or that dmsetup cannot describe, is skipped with a WARNING: teardown
    goes on with the rest (IP-11).
    """
    wanted = frozenset(devnums)
    if not wanted:
        return ()
    found: list[tuple[str, str | None]] = []
    for kname in _dm_knames(ctx):
        dm_devnum = blockdev.devnum(ctx, kname)
        if dm_devnum is None:
            continue
        dependencies = _dependencies(ctx, dm_devnum)
        if dependencies is not None and not wanted.isdisjoint(dependencies):
            found.append((dm_devnum, blockdev.dm_name(ctx, kname)))
    return tuple(found)


def mapping_on_container(
    ctx: "Context", container_kname: str
) -> tuple[str, str | None] | None:
    """``(dm kname, dm name)`` of the mapping held on a present container, or None.

    Holders that are not device-mapper devices (md, for example) are not
    mappings. When there are several, the lowest kname is returned.
    """
    for holder in blockdev.holders(ctx, container_kname):
        if _DM_KNAME.fullmatch(holder):
            return holder, blockdev.dm_name(ctx, holder)
    return None


def wait_inner_ready(
    ctx: "Context", dm_kname: str, *, timeout: float = INNER_READY_TIMEOUT
) -> BlockDevice | None:
    """The opened mapping once lsblk reports its inner filesystem type (DD-29).

    cryptsetup waits for udev, but the inner type may still be unknown, and
    the mount chain needs it. lsblk is asked every ``POLL_INTERVAL`` seconds
    until ``timeout`` has passed on the context clock; None then. An lsblk
    failure raises ``ToolError``.
    """
    blockdev.validate_kname(dm_kname)
    deadline = ctx.clock.monotonic() + timeout
    while True:
        device = blockdev.read_tree(ctx).devices.get(dm_kname)
        if device is not None and device.fstype is not None:
            return device
        remaining = deadline - ctx.clock.monotonic()
        if remaining <= 0:
            log.warning("%s: no inner filesystem type after %s s", dm_kname, timeout)
            return None
        time.sleep(min(POLL_INTERVAL, remaining))


def _unlock(ctx: "Context", command: Command, what: str) -> UnlockOutcome:
    result = ctx.runner.run(command)
    if result.returncode == 0:
        return UnlockOutcome.OPENED
    if result.returncode == EXIT_REJECTED:
        log.info("cryptsetup %s: key rejected", what)
        return UnlockOutcome.REJECTED
    log.error("cryptsetup %s failed: %s", what, _describe(result))
    return UnlockOutcome.FAILED


def _describe(result: CommandResult) -> str:
    return (
        f"exit {result.returncode}, timed out {result.timed_out}, "
        f"not found {result.not_found}: {result.err_text().strip()}"
    )


def _absolute(path: str) -> str:
    """``path`` itself; a positional path given to a tool must start with ``/``."""
    if not path.startswith("/"):
        raise ValueError(f"must be an absolute path: {path!r}")
    return path


def _split_devnum(devnum: str) -> tuple[str, str]:
    match = _DEVNUM.fullmatch(devnum)
    if match is None:
        raise ValueError(f"not a device number: {devnum!r}")
    return match[1], match[2]


def _dm_knames(ctx: "Context") -> list[str]:
    """``dm-N`` entries of ``/sys/block``, by N; [] when it cannot be listed."""
    try:
        entries = os.listdir(ctx.paths.p(_SYS_BLOCK))
    except (FileNotFoundError, NotADirectoryError):
        return []
    numbered = [
        (int(match[1]), entry)
        for entry in entries
        if (match := _DM_KNAME.fullmatch(entry)) is not None
    ]
    return [entry for _number, entry in sorted(numbered)]


def _mapping_named(ctx: "Context", name: str) -> bool:
    return any(blockdev.dm_name(ctx, kname) == name for kname in _dm_knames(ctx))


def _dependencies(ctx: "Context", dm_devnum: str) -> frozenset[str] | None:
    """Device numbers ``dm_devnum`` sits on; None when dmsetup cannot tell."""
    major, minor = _split_devnum(dm_devnum)
    argv = (
        ctx.platform.tools.dmsetup,
        "deps",
        "-o",
        "devno",
        "-j",
        major,
        "-m",
        minor,
    )
    result = ctx.runner.run(Command(argv=argv, timeout=DMSETUP_TIMEOUT))
    if result.returncode != 0:
        log.warning("dmsetup deps %s: %s", dm_devnum, _describe(result))
        return None
    match = _DEPS_LINE.fullmatch(result.text().strip())
    pairs = _DEPS_PAIR.findall(match[2]) if match is not None else []
    if match is None or len(pairs) != int(match[1]):
        log.warning(
            "dmsetup deps %s: output not understood: %r", dm_devnum, result.text()
        )
        return None
    return frozenset(":".join(pair) for pair in pairs)
