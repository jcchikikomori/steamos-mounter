"""The dependency bundle every module takes, and its production builder.

Design Doc "model, context, platforms" (AC-052): a module that needs I/O gets
it from an explicit ``Context``, which is how tests swap in the fake runner,
platform, clock and kernel log. ``release_root`` (work plan decision item 2)
is the release the running entry point belongs to; the installer compares
``--release`` against it and fails closed when either is missing.
"""

import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from steamos_mounter import kmsg, records
from steamos_mounter.journal import setup_logging
from steamos_mounter.kmsg import KernelLog
from steamos_mounter.platforms import current_platform
from steamos_mounter.platforms.base import HostPaths, Platform
from steamos_mounter.runner import Runner, SubprocessRunner

INVOCATION_ID_VARIABLE = "INVOCATION_ID"


class Clock(Protocol):
    def monotonic(self) -> float: ...
    def now(self) -> datetime: ...


class SystemClock:
    """The real clocks: ``time.monotonic`` and the UTC wall clock."""

    def monotonic(self) -> float:
        return time.monotonic()

    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True, kw_only=True)
class Context:
    runner: Runner
    platform: Platform
    paths: HostPaths
    clock: Clock
    kmsg: KernelLog
    euid: int
    invocation_id: str | None  # systemd's INVOCATION_ID; None outside a unit
    release_root: str | None = None


def build_context(*, component: str, release_root: str | None = None) -> Context:
    """Set up logging for ``component`` and bundle the real dependencies.

    A root entry also gets the ``/run/steamos-mounter`` tree (D002): it lives
    on tmpfs and nothing else recreates it after a reboot. That step raises
    ``MounterError`` when the tree cannot be trusted; the caller reports it.
    Raises ``UnsupportedPlatformError`` off SteamOS.
    """
    setup_logging(component)
    paths = HostPaths()
    ctx = Context(
        runner=SubprocessRunner(),
        platform=current_platform(paths),
        paths=paths,
        clock=SystemClock(),
        # Opens /dev/kmsg on its first mark() only: deck commands get one too.
        kmsg=kmsg.DevKmsg(),
        euid=os.geteuid(),
        invocation_id=os.environ.get(INVOCATION_ID_VARIABLE) or None,
        release_root=release_root,
    )
    if ctx.euid == 0:
        records.ensure_runtime_dirs(ctx)
    return ctx
