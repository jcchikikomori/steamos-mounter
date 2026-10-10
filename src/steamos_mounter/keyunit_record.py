"""What one key unit run is, and its "record, journal, notify" step.

Split out of ``keyunit`` by step (Design Doc "Repository Layout": split by
step, not by layer), like ``reconcile_report`` for ``reconcile``.
``keyunit`` walks the state diagram; this module holds the run's facts, the
states it decides, and how they reach the registered volume's record, the
journal and the desktop.

- **Record** (Design Doc "Runtime State Records", Write Rules): every write
  goes through ``records.update_record`` under the per-volume lock, onto the
  registered instance's record (``registered/<uuid>``). The key unit stamps
  the volume name and the registered unit, never its own unit, since the
  record belongs to that instance; its own invocation ID goes only into
  ``mapping.key_unit_invocation_id`` (ADR-0005 D5.2). ``dialog`` holds the
  last key-dialog outcome and its time.
- **Never over an unlocked volume**: a decided state before the unlock is
  written only while no mapping is open on the container. An open mapping
  (Dolphin, or the registered instance) is the reconcile's to record.
- **Journal** (ADR-COMMON-0001): one entry per decided state with
  ``SM_EVENT=key``: NOTICE once unlocked, WARNING for "needs a key" and a
  cancel, ERROR for a rejected key or a cryptsetup failure.
- **Notify** (DD-19, K2): only outcomes ``notify.notice_for`` lists for
  ``event="key"`` (``UnlockFailed``, ``MountFailed``, ``NeedsKey``
  ``dialog_failed``), and only when the logind half of the session check
  says Desktop Mode, within the run's deadline.
"""

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from steamos_mounter import bitlocker, locks, notify, session, state
from steamos_mounter.escape import escape_path, unit_name
from steamos_mounter.journal import NOTICE, fields
from steamos_mounter.model import InstanceKind, Volume, VolumeState
from steamos_mounter.reconcile_unlock import OPENED_BY_KEY_UNIT, key_unit_name
from steamos_mounter.records import TIMESTAMP_FORMAT, Record, update_record
from steamos_mounter.routing import REGISTERED_TEMPLATE
from steamos_mounter.session import Verdict

if TYPE_CHECKING:
    from steamos_mounter.context import Context

EVENT: Final = "key"
LEVELS: Final[Mapping[VolumeState, int]] = MappingProxyType(
    {
        VolumeState.MOUNTING: NOTICE,
        VolumeState.UNLOCK_FAILED: logging.ERROR,
        VolumeState.MOUNT_FAILED: logging.ERROR,
    }
)  # every other decided state (needs a key, cancelled) is a WARNING

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Decided:
    """A record state the key unit writes, with its dialog outcome and mapping.

    ``outcome`` None keeps the record's ``dialog``; ``level`` None takes the
    state's journal level from ``LEVELS``.
    """

    state: VolumeState
    reason: str | None
    outcome: str | None
    warning: str | None = None
    mapping: Mapping[str, Any] | None = None
    level: int | None = None


@dataclass(frozen=True, slots=True)
class KeyRun:
    """One key unit run: the volume, its container partition, the prompt's reason."""

    ctx: "Context"
    device_path: str
    volume: Volume
    kname: str
    why: str  # the NeedsKey reason that started the unit (dialog.WHY)
    deadline: float

    @property
    def lock_key(self) -> str:
        return self.volume.uuid.lower()

    @property
    def device(self) -> str:
        return f"/dev/{self.kname}"

    def remaining(self) -> float:
        return self.deadline - self.ctx.clock.monotonic()

    def lock_wait(self) -> float:
        return max(self.remaining(), 0.0)

    def fields(self, decided: Decided | None = None) -> dict[str, dict[str, str]]:
        return fields(
            volume=self.volume.name,
            uuid=self.volume.uuid,
            device=self.device,
            event=EVENT,
            state=None if decided is None else decided.state.value,
            reason=None if decided is None else decided.reason,
            unit=key_unit_name(self.device_path),
        )


def record_unless_open(current: KeyRun, decided: Decided) -> bool:
    """Write and report ``decided`` unless a mapping is open; True when written."""
    with locks.volume_lock(current.ctx, current.lock_key, timeout=current.lock_wait()):
        opened = mapping_open(current)
        if not opened:
            write(current, decide(current, decided))
    if opened:
        log.log(
            NOTICE,
            "%s is unlocked already: no key dialog",
            current.volume.name,
            extra=current.fields(),
        )
        return False
    report(current, decided)
    return True


def mapping_open(current: KeyRun) -> bool:
    """A device-mapper holder on the container: unlocked, by anyone."""
    return bitlocker.mapping_on_container(current.ctx, current.kname) is not None


def write(current: KeyRun, change: Callable[[Record], None]) -> None:
    """``update_record`` on the registered record; the caller holds the volume lock."""
    registered = registered_unit(current.device_path)

    def stamped(record: Record) -> None:
        record.name = current.volume.name
        record.unit = registered
        change(record)

    update_record(current.ctx, InstanceKind.REGISTERED, current.lock_key, stamped)


def decide(current: KeyRun, decided: Decided) -> Callable[[Record], None]:
    """The change that writes ``decided``: state, words, mapping, dialog outcome."""

    def apply(record: Record) -> None:
        record.state = decided.state
        record.reason = decided.reason
        record.warning = decided.warning
        record.next_step = _next_step(current, decided)
        record.mapping = None if decided.mapping is None else dict(decided.mapping)
        if decided.outcome is not None:
            record.dialog = dialog_field(current.ctx, decided.outcome)

    return apply


def own_mapping(current: KeyRun, *, save_pending: bool) -> dict[str, Any]:
    """The key unit's own mapping (ADR-0005 D4.3): its name and invocation ID."""
    return {
        "name": bitlocker.mapping_name(current.volume.uuid),
        "kname": None,
        "devnum": None,
        "opened_by": OPENED_BY_KEY_UNIT,
        "key_unit_invocation_id": current.ctx.invocation_id,
        "save_pending": save_pending,
    }


def dialog_field(ctx: "Context", outcome: str) -> dict[str, str]:
    """The record's ``dialog``: the outcome and when it happened."""
    at = ctx.clock.now().astimezone(UTC).strftime(TIMESTAMP_FORMAT)
    return {"outcome": outcome, "at": at}


def registered_unit(device_path: str) -> str:
    """The registered instance of ``device_path``: the record's owner."""
    return unit_name(REGISTERED_TEMPLATE, escape_path(device_path))


def report(current: KeyRun, decided: Decided) -> None:
    """One journal entry for ``decided``, then its notification if it has one."""
    level = decided.level or LEVELS.get(decided.state, logging.WARNING)
    log.log(
        level,
        "%s: %s (key dialog: %s)",
        current.volume.name,
        state.words(decided.state, decided.reason),
        decided.outcome or "not shown",
        extra=current.fields(decided),
    )
    _notify(current, decided)


def _next_step(current: KeyRun, decided: Decided) -> str:
    return state.next_step(
        decided.state,
        decided.reason,
        name=current.volume.name,
        cli_root=current.ctx.platform.cli_root,
    )


def _notify(current: KeyRun, decided: Decided) -> None:
    ctx = current.ctx
    view = state.VolumeView(
        name=current.volume.name,
        uuid=current.volume.uuid,
        kind=InstanceKind.REGISTERED,
        present=True,
        path=None,
        driver=None,
        mode=None,
        state=decided.state,
        reason=decided.reason,
        warning=decided.warning,
        next_step=_next_step(current, decided),
    )
    notice = notify.notice_for(view, event=EVENT)
    if notice is None or notify.out_of_time(ctx, current.deadline):
        return
    found = session.check(ctx, need_display=False, deadline=current.deadline)
    if found.verdict is Verdict.DESKTOP:
        notify.send(ctx, notice, deadline=current.deadline)
    else:
        log.info("no Desktop Mode session: %s is not notified", current.volume.name)
