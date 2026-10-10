"""What one reconcile pass is, who owns its record, and the reporting step.

Split out of ``reconcile`` by step (Design Doc "Repository Layout": split by
step, not by layer). ``reconcile`` gathers the facts, routes and runs the
actions that mount nothing; ``reconcile_mount`` runs the mount executor; the
last executor step, "record, journal, notify", lives here because both of
them end with it.

- **Owner** (Design Doc "Locks", I007): the record key follows the instance
  (``registered/<uuid>`` or ``auto/<kname>-<major>_<minor>``); the lock key
  follows the volume (the registry UUID, else the filesystem or container
  UUID, else the record key), so the container's and the mapping's
  instances serialize on one lock.
- **Next steps**: ``state.next_step`` says ``mount --volume NAME``, which only
  a registered volume answers to. An auto record stores its own step, with
  ``mount --device /dev/<partition>`` instead.
- **Journal** (ADR-COMMON-0001): NOTICE for a decided outcome, WARNING for its
  warning, ERROR for ``MountFailed`` and ``MountTimedOut``; every entry
  carries ``SM_EVENT=reconcile`` and the volume's ``SM_*`` fields.
- **Notify** (DD-19): only states ``notify.notice_for`` lists, and only when
  the logind half of the session check says Desktop Mode. The session check
  and the send share one budget that ends ``NOTIFY_AFTER_DEADLINE`` after the
  handler deadline (80 s into the pass), so even a pass whose every command
  hangs to its timeout ends 10 s inside ``TimeoutStartSec=90``. A notification
  without time left is skipped with a WARNING (``SM_EVENT=notify``).
- **Effective trigger** (D014): a reload whose ``cli_request`` is within 120 s
  runs as ``cli``.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from steamos_mounter import notify, session, state
from steamos_mounter.blockdev import BlockDevice, syspath
from steamos_mounter.escape import escape_path, unit_name
from steamos_mounter.journal import NOTICE, fields
from steamos_mounter.locks import VOLUME_KEY
from steamos_mounter.model import InstanceKind, Trigger, Volume, VolumeState
from steamos_mounter.naming import fallback_name, sanitize_label
from steamos_mounter.records import TIMESTAMP_FORMAT, Record, update_record
from steamos_mounter.routing import (
    AUTO_TEMPLATE,
    REGISTERED_TEMPLATE,
    Route,
    RoutingInput,
)

if TYPE_CHECKING:
    from steamos_mounter.context import Context
    from steamos_mounter.mounter import ChainResult

HANDLER_DEADLINE: Final = 60.0  # ADR-0001: well below TimeoutStartSec=90
# The read-back (10 s) and the record fit in the first part of this; what is
# left is the notification's. The pass ends by 80 s, 10 s inside the 90 s.
NOTIFY_AFTER_DEADLINE: Final = 20.0
CLI_REQUEST_WINDOW: Final = 120.0
EVENT: Final = "reconcile"
FAILED_STATES: Final = frozenset(
    {VolumeState.MOUNT_FAILED, VolumeState.MOUNT_TIMED_OUT}
)
REASON_UNKNOWN: Final = "unknown"
# Warnings for a chain reason that is not a record reason code (NFR-14, AC-018).
REASON_WARNINGS: Final = {
    VolumeState.MOUNTED_RW: (
        "{name} is mounted read-write with ntfs-3g because the kernel driver did"
        " not mount it: {reason}."
    ),
    VolumeState.MOUNTED_RO: "{name} is mounted read-only: {reason}.",
    VolumeState.MOUNT_FAILED: "{name} could not be mounted: {reason}.",
}

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ReconcileOutcome:
    """What one pass decided.

    ``state`` is None when the instance owns nothing. ``reason`` is the
    journal reason (``SM_REASON``): a record reason code, a delegation
    result, or words such as where a device is mounted elsewhere.
    """

    route: Route
    state: VolumeState | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class Owner:
    """Where an owning instance keeps its record and which lock guards it.

    ``device`` is ``/dev/<kname>`` of the partition or container that names
    the volume in ``mount --device`` hints.
    """

    kind: InstanceKind
    key: str
    lock_key: str
    name: str
    uuid: str
    unit: str
    device: str


@dataclass(slots=True)
class PassState:
    """One run of ``reconcile.run``, filled in as it goes; the top-level
    catch reads it to decide what it may record."""

    ctx: "Context"
    kind: InstanceKind
    device_path: str
    trigger: Trigger
    deadline: float
    inp: RoutingInput | None = None
    route: Route | None = None
    owner: Owner | None = None
    owns: bool = False  # the owner's record may be created
    outcome: ReconcileOutcome | None = None  # set once the final record is written

    def remaining(self) -> float:
        return self.deadline - self.ctx.clock.monotonic()

    def unit(self) -> str:
        """This instance's unit: the template plus the escaped ``%f`` path."""
        template = (
            REGISTERED_TEMPLATE
            if self.kind is InstanceKind.REGISTERED
            else AUTO_TEMPLATE
        )
        return unit_name(template, escape_path(self.device_path))


@dataclass(frozen=True, slots=True)
class Report:
    """A decided state as the record, the journal and ``list`` show it.

    ``reason`` is a record reason code (``state.KNOWN_REASONS``) or None;
    ``journal_reason`` is what ``SM_REASON`` and the outcome carry.
    """

    state: VolumeState
    reason: str | None
    journal_reason: str | None
    warning: str | None
    path: str | None
    driver: str | None = None
    mode: str | None = None
    notify: bool = True


def record_key(device: BlockDevice) -> str:
    """``<kname>-<major>_<minor>``: an auto instance's record key (I007)."""
    return f"{device.kname}-{device.devnum.replace(':', '_')}"


def owner_for(
    run: PassState,
    *,
    own: BlockDevice,
    base: BlockDevice,
    named: BlockDevice,
    volume: Volume | None,
) -> Owner:
    """The owner of a volume.

    ``own`` is the instance's device (an auto record key), ``base`` the
    partition or container the volume lives on (lock key UUID, hint device),
    ``named`` the device whose label names an unregistered volume.
    """
    key = record_key(own)
    if volume is not None:
        uuid, name, lock_key = volume.uuid, volume.name, volume.uuid.lower()
    else:
        uuid = base.uuid or ""
        name = sanitize_label(named.label) or fallback_name(
            named.fstype, named.uuid, named.kname
        )
        lock_key = uuid.lower() if VOLUME_KEY.fullmatch(uuid.lower()) else key
    if run.kind is InstanceKind.REGISTERED:
        key = lock_key  # registered/<registry uuid>, the same key as the lock
    return Owner(
        kind=run.kind,
        key=key,
        lock_key=lock_key,
        name=name,
        uuid=uuid,
        unit=run.unit(),
        device=f"/dev/{base.kname}",
    )


def source_of(ctx: "Context", device: BlockDevice) -> dict[str, str | None]:
    """The record's ``source``: the teardown key (ADR-0002 D4.5)."""
    return {
        "kname": device.kname,
        "devnum": device.devnum,
        "syspath": syspath(ctx, device.kname),
    }


def write(ctx: "Context", owner: Owner, change: Callable[[Record], None]) -> Record:
    """``update_record`` stamping the owner's identity; the caller holds its lock."""

    def stamped(record: Record) -> None:
        record.name = owner.name
        record.unit = owner.unit
        record.invocation_id = ctx.invocation_id or ""
        change(record)

    return update_record(ctx, owner.kind, owner.key, stamped)


def next_step(
    ctx: "Context", owner: Owner, volume_state: VolumeState, reason: str | None
) -> str:
    """``state.next_step`` for the owner; auto volumes get ``mount --device``."""
    cli = ctx.platform.cli_root
    text = state.next_step(volume_state, reason, name=owner.name, cli_root=cli)
    if owner.kind is InstanceKind.AUTO:
        text = text.replace(
            f"{cli} mount --volume {owner.name}",
            f"{cli} mount --device {owner.device}",
        )
    return text


def apply(ctx: "Context", owner: Owner, record: Record, decided: Report) -> None:
    """Set the record's state, reason, warning and next step from ``decided``."""
    record.state = decided.state
    record.reason = decided.reason
    record.warning = decided.warning
    record.next_step = next_step(ctx, owner, decided.state, decided.reason)


def chain_report(name: str, chain: "ChainResult", target: str) -> Report:
    """The read-back as a decided state (Design Doc "Read-back and State").

    The record keeps reason codes only: a ``MountFailed`` without one is
    ``unknown``, other states keep None. The chain's own reason (a tool
    message, an exit status) then goes into the warning and ``SM_REASON``.
    """
    known = state.KNOWN_REASONS.get(chain.state, frozenset())
    code = chain.reason if chain.reason in known else None
    if chain.state is VolumeState.MOUNT_FAILED and code is None:
        code = REASON_UNKNOWN
    warning = state.warning(chain.state, code, name=name)
    template = REASON_WARNINGS.get(chain.state)
    if warning is None and template and chain.reason and chain.reason != code:
        warning = template.format(name=name, reason=chain.reason.rstrip("."))
    mounted = chain.mounted
    mode = None if mounted is None else "ro" if mounted.read_only else "rw"
    return Report(
        chain.state, code, chain.reason or None, warning, target, chain.driver, mode
    )


def effective_trigger(
    now: datetime, trigger: Trigger, record: Record | None
) -> Trigger:
    """``cli`` for a reload with a ``cli_request`` within 120 s of ``now`` (D014)."""
    request = record.cli_request if record is not None else None
    if trigger is not Trigger.RELOAD or not request:
        return trigger
    try:
        at = datetime.strptime(str(request.get("at")), TIMESTAMP_FORMAT)
    except ValueError:
        return trigger
    age = abs((now - at.replace(tzinfo=UTC)).total_seconds())
    return Trigger.CLI if age <= CLI_REQUEST_WINDOW else trigger


def attempt(chain: "ChainResult") -> dict[str, Any]:
    """The record's ``attempt``: probe, steps tried, steps the guard skipped."""
    probe = chain.probe
    tried = [outcome for outcome in chain.outcomes if outcome.result != "skipped"]
    skipped = [outcome for outcome in chain.outcomes if outcome.result == "skipped"]
    return {
        "probe": None
        if probe is None
        else {"code": probe.code, "class": probe.klass.value},
        "steps": [
            {
                "driver": outcome.step.driver.value,
                "mode": outcome.step.mode.value,
                "result": outcome.result,
                "detail": outcome.detail,
            }
            for outcome in tried
        ],
        "skipped": [
            {
                "driver": outcome.step.driver.value,
                "mode": outcome.step.mode.value,
                "detail": outcome.detail,
            }
            for outcome in skipped
        ],
    }


def finish(
    run: PassState, owner: Owner, route: Route, decided: Report, device: str
) -> ReconcileOutcome:
    """Journal ``decided``, notify when it calls for it, return the outcome.

    The record is written already; a failure from here on keeps it.
    """
    outcome = ReconcileOutcome(route, decided.state, decided.journal_reason)
    run.outcome = outcome
    journal(owner, decided, device)
    if decided.notify:
        _notify(run.ctx, owner, decided, run.deadline + NOTIFY_AFTER_DEADLINE)
    return outcome


def journal(owner: Owner, decided: Report, device: str) -> None:
    """One NOTICE (ERROR for a failure), plus a WARNING with the warning."""
    extra = fields(
        volume=owner.name,
        uuid=owner.uuid or None,
        device=device,
        event=EVENT,
        state=decided.state.value,
        reason=decided.journal_reason,
        unit=owner.unit,
    )
    words = state.words(decided.state, decided.reason)
    where = f" at {decided.path}" if decided.path else ""
    failed = decided.state in FAILED_STATES
    log.log(
        logging.ERROR if failed else NOTICE,
        "%s: %s%s",
        owner.name,
        words,
        where,
        extra=extra,
    )
    if decided.warning is not None and not failed:
        log.warning("%s", decided.warning, extra=extra)


def _notify(ctx: "Context", owner: Owner, decided: Report, deadline: float) -> None:
    view = state.VolumeView(
        name=owner.name,
        uuid=owner.uuid,
        kind=owner.kind,
        present=True,
        path=decided.path,
        driver=decided.driver,
        mode=decided.mode,
        state=decided.state,
        reason=decided.reason,
        warning=decided.warning,
        next_step=next_step(ctx, owner, decided.state, decided.reason),
    )
    notice = notify.notice_for(view, event=EVENT)
    if notice is None or notify.out_of_time(ctx, deadline):
        return
    found = session.check(ctx, need_display=False, deadline=deadline)
    if found.verdict is session.Verdict.DESKTOP:
        notify.send(ctx, notice, deadline=deadline)
    elif not notify.out_of_time(ctx, deadline):
        log.info("no Desktop Mode session: %s is not notified", owner.name)
