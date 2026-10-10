"""The ``ExecStart=``/``ExecReload=`` body: one reconcile pass for one device.

Design Doc "Device Classification and Routing", "Runtime State Records" and
"Error Handling"; ADR-0001 (exit 0, own deadline) and ADR-0002 D4 and D5.
``run`` gathers every fact in one pass (the lsblk tree, the registry, the OS
partition set, sysfs ``slaves``/``holders``/``dm/name`` and sysfs paths),
lets ``routing.route`` decide, and executes the route:

- ``REJECT``, ``IGNORE``, ``YIELD``, ``FAIL_CLOSED``, ``OWN_MAPPING``: journal
  only. Such an instance owns nothing and writes no record.
- ``DELEGATE``: ``systemd.request_reconcile``, a non-blocking reload that
  never starts a unit or waits on a job. On ``absent`` the ``dm-*`` instance
  writes the minimal ``NotMounted`` record so ``list`` shows the volume
  (I006).
- ``SKIP_LOCKED``: record ``Locked`` (AC-025). ``REFUSE_REGISTERED``: record
  ``MountFailed`` with the routing reason.
- Mount actions: ``reconcile_mount``. ``UNLOCK_REGISTERED`` and the key unit
  interplay of ``MOUNT_INNER_REGISTERED``: ``reconcile_unlock``.

``run`` never raises (exit-0 discipline): its one broad handler logs the
error with the traceback and, when the instance owns a record (or a
registered instance already has one), records ``MountFailed`` with
``probe_failed`` for a failed tool query or ``internal_error`` otherwise.
The write-ahead target stays in the record, so teardown still finds it.
"""

import dataclasses
import logging
import os
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from steamos_mounter import blockdev, config, locks, routing, systemd
from steamos_mounter import reconcile_report as report
from steamos_mounter.blockdev import KNAME_RE, BlockDevice
from steamos_mounter.errors import MounterError, RegistryError, ToolError
from steamos_mounter.journal import NOTICE, fields
from steamos_mounter.locks import VOLUME_KEY
from steamos_mounter.model import InstanceKind, Registry, Trigger, VolumeState
from steamos_mounter.reconcile_mount import mount
from steamos_mounter.reconcile_report import CLI_REQUEST_WINDOW as CLI_REQUEST_WINDOW
from steamos_mounter.reconcile_report import HANDLER_DEADLINE as HANDLER_DEADLINE
from steamos_mounter.reconcile_report import ReconcileOutcome as ReconcileOutcome
from steamos_mounter.reconcile_unlock import mount_inner_registered, unlock
from steamos_mounter.records import Record, record_path, update_record
from steamos_mounter.routing import Action, Route, RoutingInput

if TYPE_CHECKING:
    from steamos_mounter.context import Context

ERROR_LOCK_WAIT: Final = 5.0
REASON_INTERNAL: Final = "internal_error"
REASON_PROBE_FAILED: Final = "probe_failed"
NO_PARTITION_INSTANCE: Final = "no_partition_instance"
ABSENT: Final = "absent"
INTERNAL_ERROR: Final = "internal error"
JOURNAL_LEVELS: Final[Mapping[Action, int]] = MappingProxyType(
    {Action.REJECT: logging.WARNING, Action.FAIL_CLOSED: logging.ERROR}
)

log = logging.getLogger(__name__)

Handler = Callable[[report.PassState, RoutingInput, Route], ReconcileOutcome]


def run(
    ctx: "Context", kind: InstanceKind, device_path: str, trigger: Trigger
) -> ReconcileOutcome:
    """One pass for the instance's device; never raises (units exit 0)."""
    current = report.PassState(
        ctx=ctx,
        kind=kind,
        device_path=device_path,
        trigger=trigger,
        deadline=ctx.clock.monotonic() + HANDLER_DEADLINE,
    )
    try:
        return _reconcile(current)
    except Exception as error:  # noqa: BLE001 - the one top-level catch (exit 0)
        return _failed(current, error)


def _reconcile(current: report.PassState) -> ReconcileOutcome:
    kname = _instance_kname(current)
    if kname is None:
        return _announce(current, Route(Action.IGNORE, routing.NOT_PRESENT), "-")
    if KNAME_RE.fullmatch(kname) is None:
        return _announce(current, Route(Action.REJECT, routing.INVALID_KNAME), kname)
    if current.kind is InstanceKind.REGISTERED:
        current.owner = _registered_owner(current, kname)
    inp = gather(current.ctx, current.kind, kname)
    current.inp = inp
    route = routing.route(inp)
    current.route = route
    return ACTION_HANDLERS[route.action](current, inp, route)


def _instance_kname(current: report.PassState) -> str | None:
    """The kname of ``%f``; None when the by-uuid link is gone.

    A link that does not resolve to ``/dev/<name>`` gives ``""``, which
    routing's first rule rejects.
    """
    if current.kind is InstanceKind.AUTO:
        return current.device_path.rpartition("/")[2]
    paths = current.ctx.paths
    link = paths.p(current.device_path)
    if not os.path.lexists(link):
        return None
    directory, _, kname = os.path.realpath(link).rpartition("/")
    return (
        kname if directory == os.path.join(os.path.realpath(paths.root), "dev") else ""
    )


def _registered_owner(current: report.PassState, kname: str) -> report.Owner | None:
    """Where a registered instance's record would be, before the registry is read.

    Used only by the top-level catch, and only when that record exists.
    """
    key = current.device_path.rpartition("/")[2].lower()
    if VOLUME_KEY.fullmatch(key) is None:
        return None
    return report.Owner(
        kind=InstanceKind.REGISTERED,
        key=key,
        lock_key=key,
        name="",
        uuid=key,
        unit=current.unit(),
        device=f"/dev/{kname}",
    )


def gather(ctx: "Context", kind: InstanceKind, kname: str) -> RoutingInput:
    """Every fact routing needs, read once.

    The installer asks the same question for each present device before it
    starts an auto instance, so the start rule and the handler never differ.
    """
    tree = blockdev.read_tree(ctx)
    registry: Registry | RegistryError
    try:
        registry = config.load(ctx)
    except RegistryError as error:
        log.warning(
            "registry unusable: %s", error.detail, extra=fields(event=report.EVENT)
        )
        registry = error
    slaves = blockdev.slaves(ctx, kname)
    holders = blockdev.holders(ctx, kname)
    mappings = [
        name for name in (kname, *holders) if name.startswith(routing.DM_PREFIX)
    ]
    dm_names = {name: dm for name in mappings if (dm := blockdev.dm_name(ctx, name))}
    syspaths = {name: path for name in slaves if (path := blockdev.syspath(ctx, name))}
    return RoutingInput(
        kind=kind,
        kname=kname,
        tree=tree,
        registry=registry,
        os_parts=ctx.platform.os_partitions(ctx, as_root=ctx.euid == 0),
        slaves=slaves,
        holders=holders,
        dm_names=MappingProxyType(dm_names),
        syspaths=MappingProxyType(syspaths),
        platform=ctx.platform,
    )


# --- actions that mount nothing ---------------------------------------------------


def _journal_only(
    current: report.PassState, inp: RoutingInput, route: Route
) -> ReconcileOutcome:
    return _announce(current, route, inp.kname)


def _announce(current: report.PassState, route: Route, kname: str) -> ReconcileOutcome:
    """REJECT, IGNORE, YIELD, FAIL_CLOSED, OWN_MAPPING: one journal entry."""
    valid = KNAME_RE.fullmatch(kname) is not None
    level = JOURNAL_LEVELS.get(route.action, NOTICE)
    log.log(
        level,
        "%s %r: %s",
        route.action,
        kname,
        route.reason,
        extra=fields(
            device=f"/dev/{kname}" if valid else None,
            event=report.EVENT,
            reason=route.reason,
        ),
    )
    return ReconcileOutcome(route, None, route.reason)


def _delegate(
    current: report.PassState, inp: RoutingInput, route: Route
) -> ReconcileOutcome:
    """DD-12: ask the partition instance to reconcile; never start it (D006)."""
    unit = route.delegate_unit or ""
    result = systemd.request_reconcile(current.ctx, unit)
    log.log(
        NOTICE,
        "/dev/%s: delegated to %s: %s",
        inp.kname,
        unit,
        result,
        extra=fields(
            device=f"/dev/{inp.kname}", event=report.EVENT, reason=result, unit=unit
        ),
    )
    if result != ABSENT:
        return ReconcileOutcome(route, None, result)
    return _no_partition_instance(current, inp, route)


def _no_partition_instance(
    current: report.PassState, inp: RoutingInput, route: Route
) -> ReconcileOutcome:
    """I006: the unlocked-but-unmounted mapping shows up in ``list``."""
    device = inp.tree.devices[inp.kname]
    container = inp.tree.devices[inp.slaves[0]]
    owner = report.owner_for(
        current, own=device, base=container, named=device, volume=route.volume
    )
    decided = report.Report(
        VolumeState.NOT_MOUNTED,
        NO_PARTITION_INSTANCE,
        NO_PARTITION_INSTANCE,
        None,
        None,
        notify=False,
    )
    hint = f"{current.ctx.platform.cli_root} mount --device /dev/{container.kname}"

    def owns_nothing(record: Record) -> None:
        record.next_step = hint
        record.mapping = None
        record.mount = None

    _record(current, owner, decided, device, owns_nothing)
    return report.finish(current, owner, route, decided, f"/dev/{device.kname}")


def _skip_locked(
    current: report.PassState, inp: RoutingInput, route: Route
) -> ReconcileOutcome:
    """AC-025: a locked container is recorded and left alone."""
    device = inp.tree.devices[inp.kname]
    owner = report.owner_for(
        current, own=device, base=device, named=device, volume=None
    )
    decided = report.Report(VolumeState.LOCKED, None, None, None, None)
    _record(current, owner, decided, device)
    return report.finish(current, owner, route, decided, f"/dev/{device.kname}")


def _refuse_registered(
    current: report.PassState, inp: RoutingInput, route: Route
) -> ReconcileOutcome:
    """Invalid entry, OS partition or a changed fstype: MountFailed, no mount."""
    device = inp.tree.devices[inp.kname]
    owner = report.owner_for(
        current, own=device, base=device, named=device, volume=route.volume
    )
    path = route.volume.path if route.volume is not None else None
    decided = report.Report(
        VolumeState.MOUNT_FAILED, route.reason, route.reason, None, path
    )
    _record(current, owner, decided, device)
    return report.finish(current, owner, route, decided, f"/dev/{device.kname}")


def _record(
    current: report.PassState,
    owner: report.Owner,
    decided: report.Report,
    source: BlockDevice,
    change: Callable[[Record], None] | None = None,
) -> None:
    """Write ``decided`` under the volume lock; the pass's final write."""
    ctx = current.ctx
    current.owner, current.owns = owner, True

    def apply(record: Record) -> None:
        record.trigger = report.effective_trigger(
            ctx.clock.now(), current.trigger, record
        )
        report.apply(ctx, owner, record, decided)
        record.cli_request = None
        record.source = report.source_of(ctx, source)
        if change is not None:
            change(record)

    with locks.volume_lock(ctx, owner.lock_key, timeout=max(current.remaining(), 0.0)):
        report.write(ctx, owner, apply)


ACTION_HANDLERS: Final[Mapping[Action, Handler]] = MappingProxyType(
    {
        Action.REJECT: _journal_only,
        Action.IGNORE: _journal_only,
        Action.FAIL_CLOSED: _journal_only,
        Action.YIELD: _journal_only,
        Action.OWN_MAPPING: _journal_only,
        Action.DELEGATE: _delegate,
        Action.SKIP_LOCKED: _skip_locked,
        Action.REFUSE_REGISTERED: _refuse_registered,
        Action.UNLOCK_REGISTERED: unlock,
        Action.MOUNT_REGISTERED: mount,
        Action.MOUNT_INNER_REGISTERED: mount_inner_registered,
        Action.AUTO_MOUNT: mount,
        Action.AUTO_MOUNT_INNER: mount,
    }
)


# --- the top-level catch ----------------------------------------------------------


def _failed(current: report.PassState, error: Exception) -> ReconcileOutcome:
    """Log ``error`` and record it where this instance owns a record."""
    code = REASON_PROBE_FAILED if isinstance(error, ToolError) else REASON_INTERNAL
    detail = error.detail if isinstance(error, MounterError) else ""
    log.error(
        "reconcile of %s failed: %s %s",
        current.device_path,
        error,
        detail,
        exc_info=error,
        extra=fields(event=report.EVENT, reason=code),
    )
    if current.outcome is not None:
        return current.outcome  # the final record is written: keep it
    route = current.route or Route(Action.FAIL_CLOSED, f"{INTERNAL_ERROR}: {code}")
    recorded = _record_failure(current, code)
    return ReconcileOutcome(route, VolumeState.MOUNT_FAILED if recorded else None, code)


def _record_failure(current: report.PassState, code: str) -> bool:
    ctx = current.ctx
    owner = current.owner
    if owner is None:
        return False
    if not current.owns and not record_path(ctx, owner.kind, owner.key).exists():
        return False

    def failed(record: Record) -> None:
        named = dataclasses.replace(owner, name=record.name or owner.name)
        record.state = VolumeState.MOUNT_FAILED
        record.reason = code
        record.warning = None
        record.next_step = report.next_step(ctx, named, VolumeState.MOUNT_FAILED, code)

    wait = min(ERROR_LOCK_WAIT, max(current.remaining(), 0.0))
    try:
        with locks.volume_lock(ctx, owner.lock_key, timeout=wait):
            update_record(ctx, owner.kind, owner.key, failed)
    except (MounterError, OSError, ValueError) as problem:
        log.error(
            "the failure of %s could not be recorded: %s",
            owner.name or owner.key,
            problem,
            extra=fields(event=report.EVENT, reason=code),
        )
        return False
    return True
