"""What a teardown run reports, records and logs.

Split out of ``teardown`` by step (Design Doc "Repository Layout": split by
step, not by layer), like ``reconcile_report`` for ``reconcile``.
``teardown`` finds the record and undoes mounts and mappings; this module
holds the report types, the final record write ("record NotPresent or
NotMounted, busy list, service result") and the journal entries.

- **Next steps**: ``reconcile_report.next_step``, so an auto record stores
  its own ``mount --device`` step.
- **Journal** (ADR-COMMON-0001 Decision 5): one NOTICE per run with
  ``SM_EVENT=teardown`` or ``sweep`` and the volume's ``SM_*`` fields; the
  sweep adds the service result, at ERROR unless it is ``success``.
"""

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC
from typing import TYPE_CHECKING, Final

from steamos_mounter.escape import escape_path, unit_name
from steamos_mounter.journal import NOTICE, fields
from steamos_mounter.model import InstanceKind, VolumeState
from steamos_mounter.mounter import UnmountResult
from steamos_mounter.reconcile_report import Owner, next_step
from steamos_mounter.records import TIMESTAMP_FORMAT, Record
from steamos_mounter.routing import AUTO_TEMPLATE, REGISTERED_TEMPLATE

if TYPE_CHECKING:
    from steamos_mounter.context import Context

SUCCESS: Final = "success"
EVENT_STOP: Final = "teardown"
EVENT_SWEEP: Final = "sweep"
SERVICE_VARIABLES: Final = ("SERVICE_RESULT", "EXIT_CODE", "EXIT_STATUS")

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TeardownReport:
    unplugged: bool
    unmounts: tuple[UnmountResult, ...]
    closes: tuple[str, ...]
    busy: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServiceResult:
    """``$SERVICE_RESULT``, ``$EXIT_CODE`` and ``$EXIT_STATUS`` of the stopped unit."""

    result: str | None
    exit_code: str | None
    exit_status: str | None

    @classmethod
    def from_environment(cls, environ: Mapping[str, str]) -> "ServiceResult":
        """The three variables systemd gives ``ExecStopPost=``; empty means None."""
        result, exit_code, exit_status = (
            environ.get(name) or None for name in SERVICE_VARIABLES
        )
        return cls(result=result, exit_code=exit_code, exit_status=exit_status)


NOTHING: Final = TeardownReport(unplugged=False, unmounts=(), closes=(), busy=())


@dataclass(frozen=True, slots=True)
class Instance:
    """Where this instance keeps its record and which lock guards it (I007)."""

    kind: InstanceKind
    device_path: str
    key: str  # the record key
    lock_key: str
    tail: str  # the registry UUID as in %f, or the auto kname

    def unit(self) -> str:
        template = (
            REGISTERED_TEMPLATE
            if self.kind is InstanceKind.REGISTERED
            else AUTO_TEMPLATE
        )
        return unit_name(template, escape_path(self.device_path))


@dataclass(slots=True)
class Work:
    """What one run did, collected step by step."""

    unplugged: bool
    unmounts: list[UnmountResult] = field(default_factory=list)
    closes: list[str] = field(default_factory=list)
    busy: list[str] = field(default_factory=list)

    def report(self) -> TeardownReport:
        return TeardownReport(
            self.unplugged, tuple(self.unmounts), tuple(self.closes), tuple(self.busy)
        )


Change = Callable[[Record], None]


def owns_nothing(device_path: str, svc: ServiceResult | None) -> TeardownReport:
    """DD-10: no record, nothing to undo; a failed unit is still reported."""
    log.debug("%s: this instance owns nothing", device_path)
    if svc is not None and svc.result != SUCCESS:
        log.error(
            "%s: service result %s, exit code %s, exit status %s",
            device_path,
            svc.result,
            svc.exit_code,
            svc.exit_status,
            extra=fields(event=EVENT_SWEEP, reason=svc.result),
        )
    return NOTHING


def owner_for(instance: Instance, name: str, kname: object) -> Owner:
    """The reconcile owner, for ``next_step`` (auto: ``mount --device``).

    ``kname`` is the recorded source; an auto instance falls back to its own.
    """
    registered = instance.kind is InstanceKind.REGISTERED
    if not isinstance(kname, str):
        kname = "" if registered else instance.tail
    return Owner(
        kind=instance.kind,
        key=instance.key,
        lock_key=instance.lock_key,
        name=name,
        uuid=instance.key if registered else "",
        unit=instance.unit(),
        device=f"/dev/{kname}" if kname else "",
    )


def settle(
    ctx: "Context", owner: Owner, saved: Record, work: Work, reason: str | None
) -> None:
    """The final state: ``NotPresent`` after an unplug, else ``NotMounted``."""
    state = VolumeState.NOT_PRESENT if work.unplugged else VolumeState.NOT_MOUNTED
    saved.state = state
    saved.reason = reason
    saved.warning = None
    saved.next_step = next_step(ctx, owner, state, reason)
    saved.busy = list(work.busy)


def with_service(ctx: "Context", change: Change, svc: ServiceResult | None) -> Change:
    """``change``, plus the sweep's service result stamped with the time now."""
    if svc is None:
        return change
    stamp = ctx.clock.now().astimezone(UTC).strftime(TIMESTAMP_FORMAT)

    def stamped(saved: Record) -> None:
        change(saved)
        saved.service = {
            "result": svc.result,
            "exit_code": svc.exit_code,
            "exit_status": svc.exit_status,
            "at": stamp,
        }

    return stamped


def _volume_fields(
    instance: Instance, record: Record, event: str, reason: str | None
) -> dict[str, dict[str, str]]:
    kname = (record.source or {}).get("kname")
    return fields(
        volume=record.name or None,
        uuid=instance.key if instance.kind is InstanceKind.REGISTERED else None,
        device=f"/dev/{kname}" if isinstance(kname, str) else None,
        event=event,
        state=record.state.value,
        reason=reason,
        unit=record.unit or None,
    )


def log_service(instance: Instance, record: Record, svc: ServiceResult) -> None:
    """ADR-COMMON-0001 Decision 5: a result other than ``success`` is an ERROR."""
    log.log(
        NOTICE if svc.result == SUCCESS else logging.ERROR,
        "%s: service result %s, exit code %s, exit status %s",
        record.name or instance.key,
        svc.result,
        svc.exit_code,
        svc.exit_status,
        extra=_volume_fields(instance, record, EVENT_SWEEP, svc.result),
    )


def journal(
    instance: Instance,
    record: Record,
    report: TeardownReport,
    svc: ServiceResult | None,
) -> None:
    """One NOTICE per run that owned a record: what was undone and what is busy."""
    event = EVENT_STOP if svc is None else EVENT_SWEEP
    how = "unplugged" if report.unplugged else "stopped"
    log.log(
        NOTICE,
        "%s: %s: %d unmounted, closed %s, busy %s",
        record.name or instance.key,
        how,
        len(report.unmounts),
        list(report.closes),
        list(report.busy),
        extra=_volume_fields(instance, record, event, record.reason),
    )
