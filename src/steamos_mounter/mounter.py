"""Mount options, driver argv, the NTFS chain and unmount.

Design Doc "NTFS Chain, Mount Options and Read-back", "Teardown" (timeouts),
IP-07 to IP-09 and ADR-0003 Decisions 2 to 7. The mount base and target
directories live in ``mountdirs`` and are re-exported here.

- Options come only from ``DRIVER_OPTIONS``, led by ``nosuid,nodev`` unless a
  registered volume opts out of one; never ``noexec``, ``force`` or
  ``remove_hiberfile`` (AC-079). Kernel drivers run as ``mount -i -t``;
  ntfs-3g runs as its own binary, so its exit code and messages come back.
- ``run_chain`` probes once when any step writes, lets ``ntfs.plan`` drop the
  kernel rw steps of an unsafe volume, and runs the rest in order. A step
  counts only when ``findmnt --mountpoint`` shows this device at the target
  (exit 0 without a mount is a failure); driver and mode come from that
  read-back (AC-063). The reason is the first conclusive source: probe
  class, ntfs-3g ("unsafe state", "Fixing", exit 14 or 15), the kernel's
  ntfs3 dirty line since the step's mark, mount(8)'s message or exit
  status, else ``unknown``.
"""

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal

from steamos_mounter import mounts, ntfs
from steamos_mounter.blockdev import BlockDevice, validate_kname
from steamos_mounter.journal import fields
from steamos_mounter.model import Driver, Mode, MountInfo, Step, VolumeState
from steamos_mounter.mountdirs import ensure_mount_base as ensure_mount_base
from steamos_mounter.mountdirs import prepare_target as prepare_target
from steamos_mounter.platforms.base import SessionUser, Tools
from steamos_mounter.runner import Command, CommandResult

if TYPE_CHECKING:
    from steamos_mounter.context import Context

STEP_TIMEOUT: Final = 30.0
NORMAL_UNMOUNT_TIMEOUT: Final = 20.0
LAZY_UNMOUNT_TIMEOUT: Final = 10.0
NTFS_FSTYPE: Final = "ntfs"
FUSE_FSTYPE: Final = "fuseblk"

# --- the option table (Design Doc "Mount Options per Driver") ---------------------

READ_ONLY_OPTION: Final = "ro"
NOSUID: Final = "nosuid"
NODEV: Final = "nodev"
_OWNERSHIP: Final = ("uid={uid}", "gid={gid}", "umask=0022")
DRIVER_OPTIONS: Final[Mapping[Driver, tuple[str, ...]]] = MappingProxyType(
    {
        Driver.NTFS3: (*_OWNERSHIP, "windows_names"),
        Driver.NTFS3G: (*_OWNERSHIP, "windows_names"),
        Driver.NTFS: _OWNERSHIP,
        Driver.EXFAT: (*_OWNERSHIP, "iocharset=utf8", "errors=remount-ro"),
        Driver.VFAT: (*_OWNERSHIP, "shortname=mixed", "utf8", "flush"),
        Driver.BTRFS: (),  # on-disk ownership as-is (AC-036)
    }
)
READ_ONLY_DRIVERS: Final = frozenset(ntfs.NTFS_DRIVERS)
KERNEL_NTFS_DRIVERS: Final = frozenset({Driver.NTFS3, Driver.NTFS})
NEVER_OPTIONS: Final = frozenset({"noexec", "force", "remove_hiberfile"})
_OWNER_KEYS: Final = frozenset({"uid", "gid"})

# --- diagnostics the reason is read from ------------------------------------------

UNSAFE_TEXT: Final = "unsafe state"  # libntfs-3g volume.c, both unsafe messages
DIRTY_FIXING_TEXT: Final = "wasn't safely closed on Windows"
KERNEL_DIRTY_TEXT: Final = 'volume is dirty and "force" flag is not set!'
UMOUNT_BUSY_TEXT: Final = "target is busy"
NTFS3G_EXIT_REASONS: Final[Mapping[int, str]] = MappingProxyType(
    {14: "unsafe", 15: "dirty"}  # ntfs-3g exits with the probe's codes
)
REASON_DIRTY: Final = "dirty"
REASON_UNSAFE: Final = "unsafe"
PROBE_REASONS: Final[Mapping[ntfs.ProbeClass, str]] = MappingProxyType(
    {ntfs.ProbeClass.DIRTY: REASON_DIRTY, ntfs.ProbeClass.UNSAFE: REASON_UNSAFE}
)
REASON_HELD: Final = "held"
REASON_UNKNOWN: Final = "unknown"
REASON_DEADLINE: Final = "deadline"
NOTHING_MOUNTED: Final = "exit 0 but nothing mounted"
TIMED_OUT: Final = "timed out"
NOT_FOUND: Final = "not found"

log = logging.getLogger(__name__)

StepResult = Literal["mounted", "refused", "skipped", "timeout"]
UnmountMode = Literal["normal", "lazy", "normal-then-lazy"]


@dataclass(frozen=True, slots=True)
class StepOutcome:
    step: Step
    result: StepResult
    detail: str


@dataclass(frozen=True, slots=True)
class ChainResult:
    """``probe`` is the guard's run, None when the chain did not probe."""

    mounted: MountInfo | None
    driver: str | None
    outcomes: tuple[StepOutcome, ...]
    state: VolumeState
    reason: str
    probe: ntfs.ProbeResult | None = None


@dataclass(frozen=True, slots=True)
class UnmountResult:
    target: str
    result: Literal["unmounted", "lazy", "busy", "absent", "failed"]
    detail: str


# --- options and argv -------------------------------------------------------------


def options_for(
    driver: Driver, mode: Mode, user: SessionUser, *, nosuid: bool, nodev: bool
) -> tuple[str, ...]:
    """The option set of one step; ``nosuid=False`` or ``nodev=False`` drops one."""
    if mode is Mode.RO and driver not in READ_ONLY_DRIVERS:
        raise ValueError(f"{driver}: no read-only step exists for this driver")
    head = (READ_ONLY_OPTION,) if mode is Mode.RO else ()
    guards = tuple(
        option for option, wanted in ((NOSUID, nosuid), (NODEV, nodev)) if wanted
    )
    table = tuple(
        option.format(uid=user.uid, gid=user.gid) for option in DRIVER_OPTIONS[driver]
    )
    return head + guards + table


def step_argv(
    tools: Tools, step: Step, device: str, target: str, options: Sequence[str]
) -> tuple[str, ...]:
    """The argv of one chain step (Design Doc "Step Invocation").

    Raises ``ValueError`` for a relative positional or an option outside the
    driver's table, so nothing else can reach a mount command.
    """
    _require_absolute(device, "device")
    _require_absolute(target, "target")
    for option in options:
        if not _option_allowed(step.driver, option):
            raise ValueError(f"{step.driver}: option {option!r} is not in the table")
    joined = ("-o", ",".join(options)) if options else ()
    if step.driver is Driver.NTFS3G:
        return (tools.ntfs3g, *joined, device, target)
    return (tools.mount, "-i", "-t", str(step.driver), *joined, device, target)


def _option_allowed(driver: Driver, option: str) -> bool:
    if option in NEVER_OPTIONS or "," in option:
        return False
    if option in {READ_ONLY_OPTION, NOSUID, NODEV}:
        return option != READ_ONLY_OPTION or driver in READ_ONLY_DRIVERS
    templates = DRIVER_OPTIONS[driver]
    if option in templates:
        return True
    key, found, value = option.partition("=")
    owned = f"{key}={{{key}}}" in templates
    return bool(found) and key in _OWNER_KEYS and value.isdecimal() and owned


def _require_absolute(path: str, what: str) -> None:
    if not path.startswith("/"):
        raise ValueError(f"{what} must be an absolute path: {path!r}")


# --- the chain ----------------------------------------------------------------------


@dataclass(slots=True)
class _Evidence:
    """The first conclusive reason each diagnostic source gave."""

    ntfs3g: str | None = None
    kernel: str | None = None
    mount_status: str | None = None


@dataclass(frozen=True, slots=True)
class _Attempt:
    device: BlockDevice
    source: str  # /dev/<kname>
    target: str
    user: SessionUser
    nosuid: bool
    nodev: bool
    deadline: float
    evidence: _Evidence = field(default_factory=_Evidence)


def run_chain(
    ctx: "Context",
    *,
    device: BlockDevice,
    target: str,
    fstype: str,
    steps: Sequence[Step] | None,
    nosuid: bool,
    nodev: bool,
    deadline: float,
) -> ChainResult:
    """Mount ``device`` at ``target`` with the first step findmnt confirms.

    ``deadline`` is a ``ctx.clock.monotonic()`` time; no step starts after
    it and none runs longer than ``STEP_TIMEOUT`` or past it. Tool failures
    become step outcomes; a read-back failure raises ``ToolError``.
    """
    chain = _chain_for(fstype, steps)
    attempt = _Attempt(
        device=device,
        source=f"/dev/{validate_kname(device.kname)}",
        target=target,
        user=ctx.platform.session_user(),
        nosuid=nosuid,
        nodev=nodev,
        deadline=deadline,
    )
    if _remaining(ctx, deadline) <= 0:
        return _no_mount(VolumeState.MOUNT_TIMED_OUT, (), REASON_DEADLINE)
    probe = None
    if fstype == NTFS_FSTYPE and any(step.mode is Mode.RW for step in chain):
        probe = ntfs.run_probe(ctx, attempt.source)
    planned = ntfs.plan(chain, probe) if fstype == NTFS_FSTYPE else None
    skipped = () if planned is None else planned.skipped
    outcomes: list[StepOutcome] = []
    for step in chain:
        if step in skipped:
            outcomes.append(_skip(step, probe, attempt))
            continue
        if _remaining(ctx, deadline) <= 0:
            return _no_mount(
                VolumeState.MOUNT_TIMED_OUT, tuple(outcomes), REASON_DEADLINE, probe
            )
        outcome, mount = _run_step(ctx, step, attempt)
        outcomes.append(outcome)
        if mount is not None:
            reason = _reason(probe, attempt)
            return _mounted(step, mount, tuple(outcomes), reason, probe)
    if probe is not None and probe.klass is ntfs.ProbeClass.HELD:
        return _no_mount(
            VolumeState.MOUNTED_ELSEWHERE, tuple(outcomes), REASON_HELD, probe
        )
    reason = _reason(probe, attempt)
    return _no_mount(VolumeState.MOUNT_FAILED, tuple(outcomes), reason, probe)


def _chain_for(fstype: str, steps: Sequence[Step] | None) -> tuple[Step, ...]:
    if fstype == NTFS_FSTYPE:
        chain = ntfs.DEFAULT_CHAIN if steps is None else tuple(steps)
        if not chain:
            raise ValueError("an empty chain cannot mount anything")
        return chain
    if fstype not in {Driver.EXFAT, Driver.VFAT, Driver.BTRFS}:
        raise ValueError(f"no mount chain for fstype {fstype!r}")
    if steps is not None:
        raise ValueError(f"a drivers list applies to NTFS only, not {fstype!r}")
    return (Step(Driver(fstype), Mode.RW),)


def _remaining(ctx: "Context", deadline: float) -> float:
    return deadline - ctx.clock.monotonic()


def _skip(step: Step, probe: ntfs.ProbeResult | None, attempt: _Attempt) -> StepOutcome:
    klass = "none" if probe is None else str(probe.klass)
    log.info(
        "skipped %s %s: probe %s",
        step.driver,
        step.mode,
        klass,
        extra=fields(device=attempt.source, step=_step_name(step)),
    )
    return StepOutcome(step, "skipped", f"probe: {klass}")


def _run_step(
    ctx: "Context", step: Step, attempt: _Attempt
) -> tuple[StepOutcome, MountInfo | None]:
    options = options_for(
        step.driver, step.mode, attempt.user, nosuid=attempt.nosuid, nodev=attempt.nodev
    )
    argv = step_argv(ctx.platform.tools, step, attempt.source, attempt.target, options)
    timeout = min(STEP_TIMEOUT, _remaining(ctx, attempt.deadline))
    mark = ctx.kmsg.mark()
    result = ctx.runner.run(Command(argv=argv, timeout=timeout))
    lines: tuple[str, ...] = ()
    if step.driver in KERNEL_NTFS_DRIVERS:
        prefix = f"{step.driver}({attempt.device.kname}):"
        lines = tuple(
            line.removeprefix(prefix).strip()
            for line in ctx.kmsg.lines_since(mark, prefix=prefix)
        )
    _collect(step, result, lines, attempt.evidence)
    found = mounts.at_target(ctx, attempt.target)
    mount = found if found is not None and _is_device(found, attempt) else None
    detail = _detail(result, lines, mounted=mount is not None)
    if mount is not None:
        verdict: StepResult = "mounted"
    else:
        verdict = "timeout" if result.timed_out else "refused"
    log.info(
        "%s %s: %s %s",
        step.driver,
        step.mode,
        verdict,
        detail,
        extra=fields(device=attempt.source, step=_step_name(step)),
    )
    return StepOutcome(step, verdict, detail), mount


def _is_device(mount: MountInfo, attempt: _Attempt) -> bool:
    return bool(mounts.for_device((mount,), attempt.device, None))


def _collect(
    step: Step, result: CommandResult, lines: tuple[str, ...], evidence: _Evidence
) -> None:
    if step.driver is Driver.NTFS3G:
        evidence.ntfs3g = evidence.ntfs3g or _ntfs3g_reason(result)
        return
    if evidence.kernel is None and any(line == KERNEL_DIRTY_TEXT for line in lines):
        evidence.kernel = REASON_DIRTY
    if evidence.mount_status is None and result.returncode not in {0, None}:
        evidence.mount_status = (
            _first_line(result) or f"mount exit status {result.returncode}"
        )


def _ntfs3g_reason(result: CommandResult) -> str | None:
    text = _flat(result.err_text())
    if UNSAFE_TEXT in text:
        return REASON_UNSAFE
    if DIRTY_FIXING_TEXT in text:
        return REASON_DIRTY
    if result.returncode is None:
        return None
    return NTFS3G_EXIT_REASONS.get(result.returncode)


def _reason(probe: ntfs.ProbeResult | None, attempt: _Attempt) -> str:
    evidence = attempt.evidence
    probe_reason = None if probe is None else PROBE_REASONS.get(probe.klass)
    return (
        probe_reason
        or evidence.ntfs3g
        or evidence.kernel
        or evidence.mount_status
        or REASON_UNKNOWN
    )


def _mounted(
    step: Step,
    mount: MountInfo,
    outcomes: tuple[StepOutcome, ...],
    reason: str,
    probe: ntfs.ProbeResult | None,
) -> ChainResult:
    driver = mount.fstype
    if mount.fstype == FUSE_FSTYPE and step.driver is Driver.NTFS3G:
        driver = str(Driver.NTFS3G)
    if mount.read_only:
        state = VolumeState.MOUNTED_RO
    elif driver == Driver.NTFS3G:
        dirty = reason == REASON_DIRTY
        state = VolumeState.MOUNTED_RW_DIRTY if dirty else VolumeState.MOUNTED_RW
    else:
        state, reason = VolumeState.MOUNTED_RW, ""
    return ChainResult(mount, driver, outcomes, state, reason, probe)


def _no_mount(
    state: VolumeState,
    outcomes: tuple[StepOutcome, ...],
    reason: str,
    probe: ntfs.ProbeResult | None = None,
) -> ChainResult:
    return ChainResult(None, None, outcomes, state, reason, probe)


def _detail(result: CommandResult, lines: tuple[str, ...], *, mounted: bool) -> str:
    text = _no_exit(result) or (lines[-1] if lines else _flat(result.err_text()))
    if text or mounted:
        return text
    if result.returncode == 0:
        return NOTHING_MOUNTED
    return f"exit status {result.returncode}"


def _step_name(step: Step) -> str:
    return f"{step.driver}:{step.mode}"


def _flat(text: str) -> str:
    """``text`` on one line: ntfs-3g wraps its messages."""
    return " ".join(text.split())


def _first_line(result: CommandResult) -> str:
    return next(
        (line.strip() for line in result.err_text().splitlines() if line.strip()), ""
    )


def _no_exit(result: CommandResult) -> str:
    return TIMED_OUT if result.timed_out else NOT_FOUND if result.not_found else ""


def _result_text(result: CommandResult) -> str:
    text = _no_exit(result) or _flat(result.err_text())
    return text or f"exit status {result.returncode}"


# --- unmount ------------------------------------------------------------------------


def unmount(
    ctx: "Context", target: str, *, mode: UnmountMode, timeout: float
) -> UnmountResult:
    """Unmount ``target``: normal (20 s), lazy (10 s), or normal then lazy.

    ``timeout`` caps each ``umount`` call. ``normal`` reports a busy target as
    ``busy``; ``normal-then-lazy`` falls back to a lazy unmount only when the
    target is busy or the normal call timed out, and reports ``lazy``.
    """
    _require_absolute(target, "target")
    if mounts.at_target(ctx, target) is None:
        return UnmountResult(target, "absent", "")
    if mode == "lazy":
        return _lazy(ctx, target, timeout)
    normal = _umount(ctx, (target,), min(NORMAL_UNMOUNT_TIMEOUT, timeout))
    if normal.returncode == 0:
        return UnmountResult(target, "unmounted", "")
    busy = normal.timed_out or UMOUNT_BUSY_TEXT in normal.err_text()
    detail = _result_text(normal)
    if mode == "normal" and busy:
        return UnmountResult(target, "busy", detail)
    if mode == "normal" or not busy:
        return UnmountResult(target, "failed", detail)
    log.warning("%s is busy, unmounting it lazily", target)
    return _lazy(ctx, target, timeout)


def _lazy(ctx: "Context", target: str, timeout: float) -> UnmountResult:
    result = _umount(ctx, ("-l", target), min(LAZY_UNMOUNT_TIMEOUT, timeout))
    if result.returncode == 0:
        return UnmountResult(target, "lazy", "")
    return UnmountResult(target, "failed", _result_text(result))


def _umount(
    ctx: "Context", arguments: tuple[str, ...], timeout: float
) -> CommandResult:
    argv = (ctx.platform.tools.umount, *arguments)
    return ctx.runner.run(Command(argv=argv, timeout=timeout))
