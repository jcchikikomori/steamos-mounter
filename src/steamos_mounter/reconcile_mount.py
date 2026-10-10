"""The mount executor of a reconcile pass, step by step.

Design Doc "Device Classification and Routing" (executor steps for mount
actions), "Runtime State Records" (Write Rules, D014, DD-10, DD-11), "Locks"
and "NTFS Chain, Mount Options and Read-back". Split out of ``reconcile`` by
step. Under the per-volume lock and within the handler deadline:

1. ``ensure_mount_base`` (AC-024).
2. Held check (ADR-0002 D4.3), from one ``findmnt --list --real``: the device
   to mount (the partition or the inner mapping) at its own recorded target
   is "already mounted" (a ``pending`` target left by a pass that died after
   mounting is adopted from findmnt); mounted anywhere else is
   ``MountedElsewhere``. Holders in sysfs other than crypt mappings (LVM,
   md) are ``MountedElsewhere`` reason ``held``. A mount nobody recorded is
   never claimed, so teardown never unmounts what another tool made.
3. Effective trigger (D014): a reload whose ``cli_request`` is within 120 s
   of now runs as ``cli``. Every owning pass clears ``cli_request``.
4. ``unmounted_by_user`` (AC-033, DD-11) stops a ``reload`` only for the
   device number of the device that was unmounted, so a new mapping (a fresh
   Dolphin unlock) mounts again; ``start`` and ``cli`` clear it.
5. Write-ahead (DD-10), ``prepare_target``, holo's lock, the chain or the
   single step, read-back, record. The journal entry and the notification
   follow once the volume lock is released.

Deadline budget: ``HANDLER_DEADLINE`` (60 s) bounds both lock waits and the
chain. ``ntfs.run_probe`` has a fixed 20 s timeout the deadline cannot cap,
so a probing chain starts only with more than 20 s left; otherwise the
volume is ``MountTimedOut`` before anything runs. A step never runs past the
deadline; the read-back, the record and the journal after it are bounded by
their own timeouts, and a notification by ``report.NOTIFY_AFTER_DEADLINE``.
"""

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from steamos_mounter import blockdev, locks, mounter, mounts, naming, ntfs
from steamos_mounter import reconcile_report as report
from steamos_mounter.bitlocker import is_tool_mapping
from steamos_mounter.blockdev import BlockDevice
from steamos_mounter.errors import MounterError
from steamos_mounter.model import Mode, MountInfo, Registry, Step, Trigger, VolumeState
from steamos_mounter.mountdirs import HostPathFacts
from steamos_mounter.mounter import ChainResult
from steamos_mounter.records import Record, load_record
from steamos_mounter.routing import Action, Route, RoutingInput

if TYPE_CHECKING:
    from steamos_mounter.context import Context

# UNLOCK_REGISTERED reaches ``mount`` only once its mapping is open (reconcile_unlock).
INNER_ACTIONS: Final = frozenset(
    {Action.MOUNT_INNER_REGISTERED, Action.AUTO_MOUNT_INNER, Action.UNLOCK_REGISTERED}
)
NTFS: Final = "ntfs"
CRYPT_TYPE: Final = "crypt"
FUSE_FSTYPE: Final = "fuseblk"
FUSE_DRIVER: Final = "ntfs-3g"
PENDING: Final = "pending"
MOUNTED: Final = "mounted"
UNMOUNTED: Final = "unmounted"
OWN_STATUSES: Final = frozenset({PENDING, MOUNTED})
REASON_UNKNOWN: Final = report.REASON_UNKNOWN
REASON_HELD: Final = "held"
REASON_DEVICE_BUSY: Final = "device_busy"
REASON_NO_FREE_NAME: Final = naming.NO_FREE_NAME
TAKEN_KINDS: Final = frozenset({naming.PathKind.NON_EMPTY_DIR, naming.PathKind.OTHER})
NOT_READY: Final = (
    "{name} could not be mounted: the unlocked device {kname} has no supported"
    " filesystem yet."
)
REFUSED_TARGET: Final = "{target} cannot be used: {why}."

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _Job:
    """One mount action: the routed facts and the owner, all known."""

    run: report.PassState
    inp: RoutingInput
    route: Route
    owner: report.Owner
    device: BlockDevice  # the instance's partition or BitLocker container
    target_device: BlockDevice  # what is mounted: the partition or the mapping

    @property
    def ctx(self) -> "Context":
        return self.run.ctx


@dataclass(frozen=True, slots=True)
class _Stamp:
    """What every owning write of this pass sets besides the state."""

    trigger: Trigger
    source: dict[str, Any]
    mapping: dict[str, Any] | None

    def onto(self, record: Record) -> None:
        record.trigger = self.trigger
        record.cli_request = None  # read once, fresh or stale (D014)
        record.source = dict(self.source)
        record.mapping = None if self.mapping is None else dict(self.mapping)


def mount(
    run: report.PassState, inp: RoutingInput, route: Route
) -> report.ReconcileOutcome:
    """Run the executor for a mount action on the instance's own device."""
    device = inp.tree.devices[inp.kname]
    target_device = route.inner if route.action in INNER_ACTIONS else device
    owner = report.owner_for(
        run, own=device, base=device, named=target_device or device, volume=route.volume
    )
    run.owner, run.owns = owner, True
    with locks.volume_lock(run.ctx, owner.lock_key, timeout=max(run.remaining(), 0.0)):
        previous = _current(run.ctx, owner)
        trigger = report.effective_trigger(run.ctx.clock.now(), run.trigger, previous)
        if trigger is not run.trigger:
            log.info("%s: the reload carries a fresh CLI request", owner.name)
        if (
            target_device is None
            or target_device.fstype not in run.ctx.platform.auto_fstypes
        ):
            kept = _kept_mapping(previous, route.mapping_name, target_device)
            stamp = _Stamp(trigger, report.source_of(run.ctx, device), kept)
            decided = _not_ready(run, inp, owner, target_device, stamp)
        else:
            job = _Job(run, inp, route, owner, device, target_device)
            decided = _locked(job, previous, trigger)
    shown = f"/dev/{target_device.kname}" if target_device else owner.device
    return report.finish(run, owner, route, decided, shown)


def _not_ready(
    run: report.PassState,
    inp: RoutingInput,
    owner: report.Owner,
    target_device: BlockDevice | None,
    stamp: _Stamp,
) -> report.Report:
    """The mapping is not in the tree yet, or holds nothing this tool mounts.

    ``stamp`` keeps the recorded mapping of the same name: the opener's
    write-ahead fields (``opened_by``, the key unit's invocation id,
    ``save_pending``) outlive a reload that comes before lsblk lists ``dm-N``.
    """
    kname = target_device.kname if target_device else _mapping_kname(inp.holders)
    warning = NOT_READY.format(name=owner.name, kname=kname)
    failed = report.Report(
        VolumeState.MOUNT_FAILED, REASON_UNKNOWN, REASON_UNKNOWN, warning, None
    )

    def apply(record: Record) -> None:
        report.apply(run.ctx, owner, record, failed)
        stamp.onto(record)

    report.write(run.ctx, owner, apply)
    return failed


def _locked(job: _Job, previous: Record | None, trigger: Trigger) -> report.Report:
    mapping = _mapping(job, previous) if job.route.inner else None
    stamp = _Stamp(trigger, report.source_of(job.ctx, job.device), mapping)
    mounter.ensure_mount_base(job.ctx)
    table = mounts.table(job.ctx)
    held = _held_check(job, stamp, previous, table)
    if held is not None:
        return held
    if previous is not None and _user_unmounted(previous, job.target_device, trigger):
        log.info(
            "%s: unmounted by the user; a reload does not mount it", job.owner.name
        )
        kept = report.Report(
            previous.state,
            previous.reason,
            "unmounted by the user",
            previous.warning,
            None,
            notify=False,
        )
        return _settle(job, stamp, kept)
    return _mount(job, stamp, table, previous)


def _held_check(
    job: _Job, stamp: _Stamp, previous: Record | None, table: Sequence[MountInfo]
) -> report.Report | None:
    """Already mounted, mounted elsewhere, held, or None to go on and mount."""
    dm_name = job.route.mapping_name if job.route.inner else None
    found = mounts.for_device(table, job.target_device, dm_name)
    own = _own_target(previous)
    at_own = [row for row in found if row.target == own]
    if previous is not None and at_own:
        return _already_mounted(job, stamp, previous, at_own[-1])
    if found:
        where = found[0].target
        elsewhere = report.Report(
            VolumeState.MOUNTED_ELSEWHERE, None, f"mounted at {where}", None, where
        )
        return _settle(job, stamp, elsewhere, _release_own_mount)
    holders = _foreign_holders(job)
    if holders:
        held = report.Report(
            VolumeState.MOUNTED_ELSEWHERE,
            REASON_HELD,
            f"held by {', '.join(holders)}",
            None,
            None,
        )
        return _settle(job, stamp, held, _release_own_mount)
    return None


def _mount(
    job: _Job, stamp: _Stamp, table: Sequence[MountInfo], previous: Record | None
) -> report.Report:
    try:
        target = _target(job, table)
    except naming.NoFreeNameError:
        failed = report.Report(
            VolumeState.MOUNT_FAILED,
            REASON_NO_FREE_NAME,
            REASON_NO_FREE_NAME,
            None,
            None,
        )
        return _settle(job, stamp, failed)
    _write_ahead(job, stamp, target, previous)
    try:
        if mounter.prepare_target(job.ctx, target):
            report.write(job.ctx, job.owner, _created_dir)
    except MounterError as error:
        why = REFUSED_TARGET.format(target=target, why=error.user_message.rstrip("."))
        refused = report.Report(
            VolumeState.MOUNT_FAILED, REASON_UNKNOWN, REASON_UNKNOWN, why, target
        )
        return _settle(job, stamp, refused, _not_mounted)
    holo_wait = min(locks.AUTOMOUNT_WAIT, max(job.run.remaining(), 0.0))
    try:
        # holo's lock is named after the physical partition, also for a mapping.
        with locks.automount_lock(job.ctx, job.device.kname, timeout=holo_wait):
            chain = _chain(job, target)
    except locks.LockTimeout:
        busy = report.Report(
            VolumeState.MOUNT_FAILED,
            REASON_DEVICE_BUSY,
            REASON_DEVICE_BUSY,
            None,
            target,
        )
        return _settle(job, stamp, busy, _not_mounted)
    return _chain_outcome(job, stamp, chain, target)


def _chain(job: _Job, target: str) -> ChainResult:
    volume = job.route.volume
    fstype = str(job.target_device.fstype)
    steps = volume.drivers if volume is not None and fstype == NTFS else None
    if _probes(fstype, steps) and job.run.remaining() <= ntfs.PROBE_TIMEOUT:
        log.info("%s: no time left for the %s s probe", target, ntfs.PROBE_TIMEOUT)
        return ChainResult(
            None, None, (), VolumeState.MOUNT_TIMED_OUT, mounter.REASON_DEADLINE
        )
    return mounter.run_chain(
        job.ctx,
        device=job.target_device,
        target=target,
        fstype=fstype,
        steps=steps,
        nosuid=volume.nosuid if volume is not None else True,
        nodev=volume.nodev if volume is not None else True,
        deadline=job.run.deadline,
    )


def _probes(fstype: str, steps: Sequence[Step] | None) -> bool:
    chain = ntfs.DEFAULT_CHAIN if steps is None else steps
    return fstype == NTFS and any(step.mode is Mode.RW for step in chain)


def _chain_outcome(
    job: _Job, stamp: _Stamp, chain: ChainResult, target: str
) -> report.Report:
    decided = report.chain_report(job.owner.name, chain, target)

    def result(record: Record) -> None:
        record.mount = dict(
            record.mount or {},
            status=MOUNTED if chain.mounted is not None else UNMOUNTED,
            driver=chain.driver,
            mode=decided.mode,
        )
        record.attempt = report.attempt(chain)

    return _settle(job, stamp, decided, result)


# --- record writes ----------------------------------------------------------------


def _settle(
    job: _Job,
    stamp: _Stamp,
    decided: report.Report,
    change: Callable[[Record], None] | None = None,
) -> report.Report:
    """Write ``decided`` with this pass's stamp: the pass's final write."""

    def apply(record: Record) -> None:
        report.apply(job.ctx, job.owner, record, decided)
        stamp.onto(record)
        if change is not None:
            change(record)

    report.write(job.ctx, job.owner, apply)
    return decided


def _write_ahead(
    job: _Job, stamp: _Stamp, target: str, previous: Record | None
) -> None:
    """DD-10: the target is on disk before the first chain step runs."""
    before = previous.mount if previous is not None and previous.mount else {}
    kept = bool(before.get("created_dir")) and before.get("target") == target
    mounting = report.Report(VolumeState.MOUNTING, None, None, None, target)

    def ahead(record: Record) -> None:
        report.apply(job.ctx, job.owner, record, mounting)
        stamp.onto(record)
        record.unmounted_by_user = None
        record.mount = {
            "status": PENDING,
            "target": target,
            "device": f"/dev/{job.target_device.kname}",
            "devnum": job.target_device.devnum,
            "driver": None,
            "mode": None,
            "created_dir": kept,
        }
        record.attempt = {"probe": None, "steps": [], "skipped": []}

    report.write(job.ctx, job.owner, ahead)


def _created_dir(record: Record) -> None:
    record.mount = dict(record.mount or {}, created_dir=True)


def _not_mounted(record: Record) -> None:
    record.mount = dict(record.mount or {}, status=UNMOUNTED)


def _release_own_mount(record: Record) -> None:
    """The device is mounted elsewhere now: no own mount is left."""
    if record.mount and record.mount.get("status") in OWN_STATUSES:
        _not_mounted(record)


def _already_mounted(
    job: _Job, stamp: _Stamp, previous: Record, row: MountInfo
) -> report.Report:
    """Idempotent pass: keep the outcome; adopt a ``pending`` mount from findmnt."""
    driver = FUSE_DRIVER if row.fstype == FUSE_FSTYPE else row.fstype
    mode = "ro" if row.read_only else "rw"
    adopt = (previous.mount or {}).get("status") != MOUNTED
    log.info("%s is already mounted at %s", job.owner.name, row.target)
    if adopt:
        found = VolumeState.MOUNTED_RO if row.read_only else VolumeState.MOUNTED_RW
        kept = report.Report(found, None, None, None, row.target, driver, mode, False)
    else:
        kept = report.Report(
            previous.state,
            previous.reason,
            previous.reason,
            previous.warning,
            row.target,
            driver,
            mode,
            notify=False,
        )

    def adopted(record: Record) -> None:
        record.unmounted_by_user = None
        if adopt:
            record.mount = dict(
                record.mount or {}, status=MOUNTED, driver=driver, mode=mode
            )

    return _settle(job, stamp, kept, adopted)


# --- facts ------------------------------------------------------------------------


def _current(ctx: "Context", owner: report.Owner) -> Record | None:
    found = load_record(ctx, owner.kind, owner.key)
    return found if isinstance(found, Record) else None


def _own_target(previous: Record | None) -> str | None:
    mount = previous.mount if previous is not None else None
    if not mount or mount.get("status") not in OWN_STATUSES:
        return None
    target = mount.get("target")
    return target if isinstance(target, str) else None


def _user_unmounted(
    previous: Record, target_device: BlockDevice, trigger: Trigger
) -> bool:
    """AC-033 within DD-11's scope: only a reload, only the same device number."""
    flag = previous.unmounted_by_user
    if trigger is not Trigger.RELOAD or not flag:
        return False
    return flag.get("devnum") == target_device.devnum


def _foreign_holders(job: _Job) -> list[str]:
    """sysfs holders that are not a crypt mapping (ADR-0002 D4, I013)."""
    devices = job.inp.tree.devices
    return [
        holder
        for holder in blockdev.holders(job.ctx, job.target_device.kname)
        if (known := devices.get(holder)) is None or known.type != CRYPT_TYPE
    ]


def _mapping(job: _Job, previous: Record | None) -> dict[str, Any]:
    """The record's ``mapping``; an opener's write-ahead fields are kept."""
    name = job.route.mapping_name
    inner = job.target_device
    kept = _kept_mapping(previous, name, inner)
    if kept is not None:
        return kept
    return {
        "name": name,
        "kname": inner.kname,
        "devnum": inner.devnum,
        "opened_by": "handler" if is_tool_mapping(name) else "other",
        "key_unit_invocation_id": None,
        "save_pending": False,
    }


def _kept_mapping(
    previous: Record | None, name: str | None, inner: BlockDevice | None
) -> dict[str, Any] | None:
    """The recorded mapping when it has ``name``, with ``inner``'s kname and devnum."""
    existing = previous.mapping if previous is not None else None
    if not existing or name is None or existing.get("name") != name:
        return None
    if inner is None:
        return dict(existing)
    return dict(existing, kname=inner.kname, devnum=inner.devnum)


def _mapping_kname(holders: Sequence[str]) -> str:
    return next((holder for holder in holders if holder.startswith("dm-")), "-")


def _target(job: _Job, table: Sequence[MountInfo]) -> str:
    """The fixed path, or a free ``<base>/<name>[-N]`` (AC-027, AC-028)."""
    volume = job.route.volume
    if volume is not None:
        return volume.path
    registry = job.inp.registry
    fixed = [v.path for v in registry.volumes] if isinstance(registry, Registry) else []
    mounted = {row.target for row in table}
    facts = HostPathFacts(job.ctx.paths)

    def taken(path: str) -> bool:
        if path in mounted or facts.kind(path) in TAKEN_KINDS:
            return True
        return any(path == other or path.startswith(other + "/") for other in fixed)

    return naming.unique_auto_path(job.ctx.platform.mount_base, job.owner.name, taken)
