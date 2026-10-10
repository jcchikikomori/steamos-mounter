"""The BitLocker steps of a reconcile pass: stored-key unlock and the key unit.

Design Doc "Device Classification and Routing" (``UNLOCK_REGISTERED``
executor, key unit interplay), "Key Store", "BitLocker Unlock and Mappings",
"Notifications", DD-10, DD-18, DD-19, DD-29; ADR-0005 D1.3, D1.4 and D5.2.
Split out of ``reconcile`` by step, like ``reconcile_mount``.

``UNLOCK_REGISTERED`` (``unlock``), under the per-volume lock:

1. ``keystore.status``. ``OK``: write the mapping name ahead (DD-10), then
   ``open_with_file`` once; the key file's path is all this process ever
   holds of the key. ``OPENED``: release the lock, ``wait_inner_ready``,
   and mount the inner device at ``volume.path`` with ``reconcile_mount``'s
   steps.
2. ``MISSING`` or ``REJECTED``: ``NeedsKey`` with ``stored_key_missing`` or
   ``stored_key_rejected``. For trigger ``start`` or ``cli`` the logind
   session check decides: ``DESKTOP`` starts the key unit with
   ``systemctl start --no-block`` once the record is written, and no
   notification is sent (the dialog replaces it); otherwise the reason is
   ``no_session`` or ``session_not_sure`` and nothing is sent. A reload,
   delegated or not, never starts the key unit and keeps the stored-key
   reason.
3. ``BAD_PERMISSIONS``: ``NeedsKey`` ``key_permissions``, no dialog, and the
   DD-19 notification.
4. A cryptsetup failure other than a rejected key (busy, timeout, missing
   binary) is ``MountFailed`` ``unknown`` with a warning: the key may be
   fine, so no dialog is started.

``MOUNT_INNER_REGISTERED`` (``mount_inner_registered``) first settles the
key unit (ADR-0005 D5.2, J001): when it is active, the record is read under
the volume lock, and the unit is stopped with ``--no-block`` unless the
record says the key unit itself opened this tool-named mapping
(``key_unit_must_stop``). The mount follows either way.
"""

import dataclasses
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from steamos_mounter import bitlocker, keystore, locks, session, systemd
from steamos_mounter import reconcile_report as report
from steamos_mounter.bitlocker import UnlockOutcome, is_tool_mapping
from steamos_mounter.blockdev import BlockDevice
from steamos_mounter.errors import ToolError
from steamos_mounter.escape import escape_path, unit_name
from steamos_mounter.journal import NOTICE, fields
from steamos_mounter.keystore import KeyStatus
from steamos_mounter.model import InstanceKind, Trigger, Volume, VolumeState
from steamos_mounter.reconcile_mount import NOT_READY, mount
from steamos_mounter.records import Record, load_record
from steamos_mounter.routing import Route, RoutingInput

if TYPE_CHECKING:
    from steamos_mounter.context import Context

KEY_TEMPLATE: Final = "steamos-mounter-key@"
KEY_UNIT_PROPERTIES: Final = ("LoadState", "ActiveState", "InvocationID")
# ActiveState values of a key unit that may still show or be about to show a dialog.
KEY_UNIT_RUNNING: Final = frozenset({"active", "activating", "reloading"})
OPENED_BY_HANDLER: Final = "handler"
OPENED_BY_KEY_UNIT: Final = "key-unit"
DIALOG_TRIGGERS: Final = frozenset({Trigger.START, Trigger.CLI})

REASON_MISSING: Final = "stored_key_missing"
REASON_REJECTED: Final = "stored_key_rejected"
REASON_NO_SESSION: Final = "no_session"
REASON_NOT_SURE: Final = "session_not_sure"
REASON_PERMISSIONS: Final = "key_permissions"
REASON_UNKNOWN: Final = report.REASON_UNKNOWN

CAUSES: Final[Mapping[str, str]] = MappingProxyType(
    {
        REASON_MISSING: "There is no stored key",
        REASON_REJECTED: "The stored key did not work",
    }
)
NO_DIALOG: Final[Mapping[str, str]] = MappingProxyType(
    {
        REASON_NO_SESSION: "there was no Desktop Mode session for the key dialog",
        REASON_NOT_SURE: (
            "the Desktop Mode session could not be confirmed for the key dialog"
        ),
    }
)
OPEN_FAILED: Final = (
    "{name} could not be unlocked with its stored key: cryptsetup failed."
)

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _Unlock:
    """One ``UNLOCK_REGISTERED`` pass: the facts every write of it needs."""

    run: report.PassState
    owner: report.Owner
    container: BlockDevice
    volume: Volume
    trigger: Trigger

    @property
    def ctx(self) -> "Context":
        return self.run.ctx


@dataclass(frozen=True, slots=True)
class _Decision:
    """How a pass that opened nothing ends: the report and the key unit start."""

    decided: report.Report
    start_key_unit: bool = False


def key_unit_name(device_path: str) -> str:
    """``steamos-mounter-key@<escaped %f>.service``: the registered instance's name."""
    return unit_name(KEY_TEMPLATE, escape_path(device_path))


def key_unit_must_stop(
    mapping_name: str | None, record: Record | None, invocation_id: str
) -> bool:
    """ADR-0005 D5.2: True unless the active key unit opened this mapping itself.

    The key unit keeps running (its save question survives, J001) only when
    the mapping is tool-named and the record says ``opened_by = "key-unit"``
    for this mapping with the active unit's ``InvocationID``.
    """
    mapping = record.mapping if record is not None else None
    if not is_tool_mapping(mapping_name) or not mapping or not invocation_id:
        return True
    return not (
        mapping.get("name") == mapping_name
        and mapping.get("opened_by") == OPENED_BY_KEY_UNIT
        and mapping.get("key_unit_invocation_id") == invocation_id
    )


# --- MOUNT_INNER_REGISTERED: the key unit, then the mount ---------------------------


def mount_inner_registered(
    run: report.PassState, inp: RoutingInput, route: Route
) -> report.ReconcileOutcome:
    """Stop a key unit the mapping made pointless, then mount the inner device."""
    volume = route.volume
    if volume is None:  # routing gives a registered inner route only with an entry
        raise ValueError("MOUNT_INNER_REGISTERED without a registry entry")
    _settle_key_unit(run, volume, route.mapping_name)
    return mount(run, inp, route)


def _settle_key_unit(
    run: report.PassState, volume: Volume, mapping_name: str | None
) -> None:
    ctx = run.ctx
    unit = key_unit_name(run.device_path)
    try:
        properties = systemd.show(ctx, unit, KEY_UNIT_PROPERTIES)
    except ToolError as error:
        log.warning(
            "cannot tell whether %s is running: %s",
            unit,
            error.detail,
            extra=fields(unit=unit, event=report.EVENT),
        )
        return
    active = properties.get("ActiveState", "")
    if not systemd.unit_exists(properties) or active not in KEY_UNIT_RUNNING:
        return
    name = volume.name
    record = _locked_record(run, volume)
    invocation_id = properties.get("InvocationID", "")
    if not key_unit_must_stop(mapping_name, record, invocation_id):
        log.info("%s: the key unit opened it; it keeps running", name)
        return
    result = systemd.stop(ctx, [unit], block=False)
    level = NOTICE if result.returncode == 0 else logging.WARNING
    log.log(
        level,
        "%s was unlocked another way: stopping %s (exit %s)",
        name,
        unit,
        result.returncode,
        extra=fields(volume=name, unit=unit, event=report.EVENT),
    )


def _locked_record(run: report.PassState, volume: Volume) -> Record | None:
    """The registered record, read under the volume lock (the key unit's write)."""
    key = volume.uuid.lower()
    with locks.volume_lock(run.ctx, key, timeout=max(run.remaining(), 0.0)):
        found = load_record(run.ctx, InstanceKind.REGISTERED, key)
    return found if isinstance(found, Record) else None


# --- UNLOCK_REGISTERED ---------------------------------------------------------------


def unlock(
    run: report.PassState, inp: RoutingInput, route: Route
) -> report.ReconcileOutcome:
    """Open the container with its stored key and mount it, or record why not."""
    volume = route.volume
    if volume is None:  # routing gives UNLOCK_REGISTERED only with a valid entry
        raise ValueError("UNLOCK_REGISTERED without a registry entry")
    ctx = run.ctx
    container = inp.tree.devices[inp.kname]
    owner = report.owner_for(
        run, own=container, base=container, named=container, volume=volume
    )
    run.owner, run.owns = owner, True
    key = keystore.status(ctx, volume.uuid)
    with locks.volume_lock(ctx, owner.lock_key, timeout=max(run.remaining(), 0.0)):
        found = load_record(ctx, owner.kind, owner.key)
        previous = found if isinstance(found, Record) else None
        trigger = report.effective_trigger(ctx.clock.now(), run.trigger, previous)
        step = _Unlock(run, owner, container, volume, trigger)
        opened = _open(step) if key is KeyStatus.OK else None
        decision = None
        if opened is not UnlockOutcome.OPENED:
            decision = _not_opened(step, key, opened)
            _write_final(step, decision.decided)
    if decision is None:
        return _mount_opened(step, inp, route)
    if decision.start_key_unit:
        _start_key_unit(step)
    return report.finish(run, owner, route, decision.decided, owner.device)


def _open(step: _Unlock) -> UnlockOutcome:
    """DD-10: the mapping name is on disk before ``cryptsetup open`` runs."""
    ctx = step.ctx
    uuid = step.volume.uuid
    unlocking = report.Report(VolumeState.MOUNTING, None, None, None, step.volume.path)
    mapping = {
        "name": bitlocker.mapping_name(uuid),
        "kname": None,
        "devnum": None,
        "opened_by": OPENED_BY_HANDLER,
        "key_unit_invocation_id": None,
        "save_pending": False,
    }

    def ahead(record: Record) -> None:
        report.apply(ctx, step.owner, record, unlocking)
        record.trigger = step.trigger
        record.source = report.source_of(ctx, step.container)
        record.mapping = mapping
        # A mapping opened now is a new device: an older "unmounted by the
        # user" mark (DD-11) is about a mapping that no longer exists.
        record.unmounted_by_user = None

    report.write(ctx, step.owner, ahead)
    return bitlocker.open_with_file(
        ctx,
        f"/dev/{step.container.kname}",
        uuid,
        str(keystore.key_path(ctx, uuid)),
    )


def _not_opened(
    step: _Unlock, key: KeyStatus, opened: UnlockOutcome | None
) -> _Decision:
    if key is KeyStatus.BAD_PERMISSIONS:
        return _Decision(
            report.Report(
                VolumeState.NEEDS_KEY,
                REASON_PERMISSIONS,
                REASON_PERMISSIONS,
                None,
                None,
            )
        )
    if opened is UnlockOutcome.FAILED:
        warning = OPEN_FAILED.format(name=step.owner.name)
        return _Decision(
            report.Report(
                VolumeState.MOUNT_FAILED, REASON_UNKNOWN, REASON_UNKNOWN, warning, None
            )
        )
    cause = REASON_REJECTED if opened is UnlockOutcome.REJECTED else REASON_MISSING
    return _needs_key(step, cause)


def _needs_key(step: _Unlock, cause: str) -> _Decision:
    """AC-014, AC-075, ADR-0005 D1.3: the key unit or a recorded reason, one of them."""
    sentence = CAUSES[cause]
    if step.trigger not in DIALOG_TRIGGERS:
        decided = _needs_key_report(cause, f"{sentence}.")
        return _Decision(decided)
    verdict = session.check(step.ctx, need_display=False).verdict
    if verdict is session.Verdict.DESKTOP:
        return _Decision(_needs_key_report(cause, f"{sentence}."), start_key_unit=True)
    reason = REASON_NO_SESSION if verdict is session.Verdict.NONE else REASON_NOT_SURE
    return _Decision(_needs_key_report(reason, f"{sentence}, and {NO_DIALOG[reason]}."))


def _needs_key_report(reason: str, warning: str) -> report.Report:
    # No notification: a started key unit's dialog replaces it, and without a
    # session there is nobody to tell (Game Mode deferred, AC-074).
    return report.Report(
        VolumeState.NEEDS_KEY, reason, reason, warning, None, notify=False
    )


def _write_final(step: _Unlock, decided: report.Report) -> None:
    """The pass's final write when nothing was opened: no mapping exists."""
    ctx = step.ctx

    def apply(record: Record) -> None:
        report.apply(ctx, step.owner, record, decided)
        record.trigger = step.trigger
        record.cli_request = None  # read once, fresh or stale (D014)
        record.source = report.source_of(ctx, step.container)
        record.mapping = None

    report.write(ctx, step.owner, apply)


def _start_key_unit(step: _Unlock) -> None:
    """``systemctl start --no-block``: the start job never waits on a human."""
    unit = key_unit_name(step.run.device_path)
    result = systemd.start(step.ctx, unit, block=False)
    extra = fields(volume=step.owner.name, unit=unit, event=report.EVENT)
    if result.returncode == 0:
        log.info("%s: key dialog unit %s started", step.owner.name, unit, extra=extra)
        return
    log.warning(
        "%s: the key dialog unit %s did not start: exit %s, %s",
        step.owner.name,
        unit,
        result.returncode,
        result.err_text().strip(),
        extra=extra,
    )


# --- after the open: wait for the inner filesystem, then mount ---------------------


def _mount_opened(
    step: _Unlock, inp: RoutingInput, route: Route
) -> report.ReconcileOutcome:
    """DD-29, then ``reconcile_mount.mount`` on the mapping at ``volume.path``."""
    ctx = step.ctx
    found = bitlocker.mapping_on_container(ctx, step.container.kname)
    inner = None
    if found is not None:
        wait = min(bitlocker.INNER_READY_TIMEOUT, max(step.run.remaining(), 0.0))
        inner = bitlocker.wait_inner_ready(ctx, found[0], timeout=wait)
    if inner is None or inner.fstype not in ctx.platform.auto_fstypes:
        return _inner_not_ready(step, route, found[0] if found else None)
    opened = dataclasses.replace(
        route, inner=inner, mapping_name=bitlocker.mapping_name(step.volume.uuid)
    )
    return mount(step.run, inp, opened)


def _inner_not_ready(
    step: _Unlock, route: Route, kname: str | None
) -> report.ReconcileOutcome:
    """MountFailed ``unknown``; the record keeps the open mapping for teardown."""
    ctx = step.ctx
    warning = NOT_READY.format(name=step.owner.name, kname=kname or "-")
    failed = report.Report(
        VolumeState.MOUNT_FAILED, REASON_UNKNOWN, REASON_UNKNOWN, warning, None
    )

    def apply(record: Record) -> None:
        report.apply(ctx, step.owner, record, failed)
        record.cli_request = None
        record.mapping = _with_kname(record.mapping, kname)

    with locks.volume_lock(
        ctx, step.owner.lock_key, timeout=max(step.run.remaining(), 0.0)
    ):
        report.write(ctx, step.owner, apply)
    return report.finish(step.run, step.owner, route, failed, step.owner.device)


def _with_kname(
    mapping: dict[str, Any] | None, kname: str | None
) -> dict[str, Any] | None:
    if mapping is None or kname is None:
        return mapping
    return dict(mapping, kname=kname)
