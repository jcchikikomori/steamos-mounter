"""The key dialog unit: ask for a BitLocker key in Desktop Mode, unlock, offer to save.

Design Doc "Key Dialog Unit" (state diagram, unlock and record, save, K2,
one at a time, unplug), "Key Dialog Path", "Locks", "Notifications" and the
Data Contract ``keyunit.run``; ADR-0005 D1, D4 and D5. ``internal key PATH``
runs ``run`` in ``steamos-mounter-key@.service`` (``Type=exec``,
``RuntimeMaxSec=300``); ``internal key-stop PATH`` runs ``stop_post``.

``run`` follows the state diagram within ``KEY_UNIT_DEADLINE``:

1. The registry entry (a registered BitLocker container) and its partition
   from the by-uuid link; anything else is logged and nothing is shown.
2. ``session.check(need_display=True)``: anything but ``DESKTOP`` records
   ``NeedsKey`` ``no_session`` or ``session_not_sure`` (AC-075, AC-076).
3. The dialog lock (one dialog at a time). It is waited for only while the
   password dialog can still run its whole timer before the deadline; after
   that, ``NeedsKey`` keeps the stored-key reason.
4. Under the volume lock: a mapping that is open already (a Dolphin unlock)
   ends the run; otherwise ``NeedsKey`` ``dialog_open``, dialog ``shown``.
5. ``dialog.ask_password``: cancelled and timed out are ``UnlockCancelled``;
   failed is ``NeedsKey`` ``dialog_failed`` with the K2 notification.
6. Under the volume lock: no mapping may be open; the mapping name is
   written ahead (DD-10) and ``open_with_secret`` runs once. Opened: the
   record says ``opened_by`` ``key-unit`` with this unit's invocation ID,
   ``save_pending`` true and dialog ``unlocked`` before any reload (J001).
   Rejected: ``UnlockFailed``. Any other failure: ``MountFailed``
   ``unknown``, unless a mapping appeared meanwhile (unlocked another way).
7. With the volume lock released: ``systemd.request_reconcile`` on the
   registered instance, whose reload mounts the inner volume (AC-071).
8. The save question, only while the session is still Desktop Mode and at
   least ``dialog.SAVE_TIMEOUT`` is left: Yes runs ``keystore.store`` (the
   open was the FR-16 test); anything else is "not saved". ``save_pending``
   is cleared either way, also when the unit is being stopped.

No dialog is ever open while the volume lock is held (ADR-0005 D1.6,
NFR-02); the dialog lock is held from before the password dialog until
after the save question. The typed key lives in one ``SecretBytes`` whose
``with`` block clears it on every path, ``SystemExit`` from SIGTERM
included; it reaches cryptsetup's stdin and, after a Yes, the 0600 key file.
Every decided outcome is one journal entry with ``SM_EVENT=key``; the
record, journal and notification step lives in ``keyunit_record`` (split
by step, like ``reconcile_report``).
"""

import contextlib
import logging
import os
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from steamos_mounter import bitlocker, config, dialog, keystore, locks, session, systemd
from steamos_mounter.bitlocker import UnlockOutcome
from steamos_mounter.blockdev import KNAME_RE
from steamos_mounter.dialog import Outcome
from steamos_mounter.errors import MounterError, RegistryError, ToolError
from steamos_mounter.journal import NOTICE, fields
from steamos_mounter.keystore import KeyStatus
from steamos_mounter.keyunit_record import (
    EVENT,
    Decided,
    KeyRun,
    decide,
    dialog_field,
    mapping_open,
    own_mapping,
    record_unless_open,
    registered_unit,
    report,
    write,
)
from steamos_mounter.model import InstanceKind, Volume, VolumeState
from steamos_mounter.reconcile_unlock import (
    CAUSES,
    NO_DIALOG,
    REASON_MISSING,
    REASON_NO_SESSION,
    REASON_NOT_SURE,
    REASON_REJECTED,
    key_unit_name,
)
from steamos_mounter.records import Record, load_record
from steamos_mounter.sensitive import SecretBytes
from steamos_mounter.session import SessionCheck, Verdict
from steamos_mounter.teardown_report import SUCCESS

if TYPE_CHECKING:
    from steamos_mounter.context import Context
    from steamos_mounter.teardown_report import ServiceResult

KEY_UNIT_DEADLINE: Final = 270.0  # ADR-0005 D1.2: inside RuntimeMaxSec=300
BITLOCKER: Final = "BitLocker"
# The password dialog's own time: its timer plus the stop of a leftover unit.
# The dialog lock is waited for only while that still fits before the deadline.
PASSWORD_BUDGET: Final = dialog.PASSWORD_TIMEOUT + dialog.STOP_TIMEOUT
# Clearing save_pending while the unit is being stopped (TimeoutStopSec=30).
STOPPING_LOCK_WAIT: Final = 5.0

REASON_DIALOG_OPEN: Final = "dialog_open"
REASON_DIALOG_FAILED: Final = "dialog_failed"
REASON_CANCELLED: Final = "dialog_cancelled"
REASON_TIMED_OUT: Final = "dialog_timed_out"
REASON_UNKNOWN: Final = "unknown"

# The record's dialog.outcome values (Design Doc "Record Schema").
SHOWN: Final = "shown"
ENTERED: Final = "entered"
UNLOCKED: Final = "unlocked"
UNLOCK_FAILED: Final = "unlock-failed"
SAVED: Final = "saved"
NOT_SAVED: Final = "not-saved"

OPEN_FAILED: Final = (
    "{name} could not be unlocked with the typed key: cryptsetup failed."
)
WAITED_TOO_LONG: Final = (
    "another key dialog was open until no time was left for this one"
)

log = logging.getLogger(__name__)


NOT_ENTERED: Final[Mapping[Outcome, Decided]] = MappingProxyType(
    {
        Outcome.CANCELLED: Decided(
            VolumeState.UNLOCK_CANCELLED, REASON_CANCELLED, Outcome.CANCELLED.value
        ),
        Outcome.TIMED_OUT: Decided(
            VolumeState.UNLOCK_CANCELLED, REASON_TIMED_OUT, Outcome.TIMED_OUT.value
        ),
        # K2: a dialog that could not be shown in a session that passed the check.
        Outcome.FAILED: Decided(
            VolumeState.NEEDS_KEY, REASON_DIALOG_FAILED, Outcome.FAILED.value
        ),
    }
)
SHOWING: Final = Decided(
    VolumeState.NEEDS_KEY, REASON_DIALOG_OPEN, SHOWN, level=logging.INFO
)


def run(ctx: "Context", device_path: str) -> None:
    """Show the key dialog for the registered BitLocker volume at ``device_path``."""
    deadline = ctx.clock.monotonic() + KEY_UNIT_DEADLINE
    current = _prepare(ctx, device_path, deadline)
    if current is None:
        return
    found = session.check(ctx, need_display=True, deadline=deadline)
    if found.verdict is not Verdict.DESKTOP:
        record_unless_open(current, _no_session(current, found.verdict))
        return
    with contextlib.ExitStack() as held:
        try:
            held.enter_context(
                locks.dialog_lock(ctx, timeout=_dialog_lock_wait(current))
            )
        except locks.LockTimeout:
            record_unless_open(current, _waited_too_long(current))
            return
        _ask(current, found)


def stop_post(ctx: "Context", device_path: str, svc: "ServiceResult") -> None:
    """``ExecStopPost=``: close the dialog by stopping its unit, log the result.

    AC-078: at an unplug ``BindsTo=`` stops the key unit and this closes the
    dialog on the screen. Nothing is stored: saving needs the save question's
    Yes, inside ``run``.
    """
    uuid = device_path.rpartition("/")[2]
    dialog.stop(ctx, uuid)
    log.log(
        NOTICE if svc.result == SUCCESS else logging.ERROR,
        "key unit for %s: service result %s, exit code %s, exit status %s",
        device_path,
        svc.result,
        svc.exit_code,
        svc.exit_status,
        extra=fields(
            uuid=uuid, event=EVENT, reason=svc.result, unit=key_unit_name(device_path)
        ),
    )


# --- before the dialog ---------------------------------------------------------------


def _prepare(ctx: "Context", device_path: str, deadline: float) -> KeyRun | None:
    """The run's volume and container partition; None when no dialog is due."""
    uuid = device_path.rpartition("/")[2]
    try:
        registry = config.load(ctx)
    except RegistryError as error:
        log.error(
            "no key dialog for %s: the registry is unusable: %s",
            device_path,
            error.detail,
            extra=fields(event=EVENT),
        )
        return None
    volume = registry.by_uuid(uuid)
    if volume is None or volume.fstype != BITLOCKER:
        log.error(
            "no key dialog for %s: not a registered BitLocker volume",
            device_path,
            extra=fields(event=EVENT),
        )
        return None
    kname = _container_kname(ctx, device_path)
    if kname is None:
        log.log(
            NOTICE,
            "%s is not present: no key dialog",
            volume.name,
            extra=fields(volume=volume.name, uuid=volume.uuid, event=EVENT),
        )
        return None
    return KeyRun(ctx, device_path, volume, kname, _why(ctx, volume), deadline)


def _container_kname(ctx: "Context", device_path: str) -> str | None:
    """The kname the by-uuid link points to; None when it is gone or odd."""
    link = ctx.paths.p(device_path)
    if not os.path.lexists(link):
        return None
    directory, _, kname = os.path.realpath(link).rpartition("/")
    dev = os.path.join(os.path.realpath(ctx.paths.root), "dev")
    if directory != dev or KNAME_RE.fullmatch(kname) is None:
        return None
    return kname


def _why(ctx: "Context", volume: Volume) -> str:
    """The recorded stored-key reason; without one, whether a key file exists."""
    found = load_record(ctx, InstanceKind.REGISTERED, volume.uuid)
    reason = found.reason if isinstance(found, Record) else None
    if reason is not None and reason in dialog.WHY:
        return reason
    missing = keystore.status(ctx, volume.uuid) is KeyStatus.MISSING
    return REASON_MISSING if missing else REASON_REJECTED


def _no_session(current: KeyRun, verdict: Verdict) -> Decided:
    reason = REASON_NO_SESSION if verdict is Verdict.NONE else REASON_NOT_SURE
    warning = f"{CAUSES[current.why]}, and {NO_DIALOG[reason]}."
    return Decided(VolumeState.NEEDS_KEY, reason, None, warning)


def _dialog_lock_wait(current: KeyRun) -> float:
    return max(current.remaining() - PASSWORD_BUDGET, 0.0)


def _waited_too_long(current: KeyRun) -> Decided:
    warning = f"{CAUSES[current.why]}, and {WAITED_TOO_LONG}."
    return Decided(VolumeState.NEEDS_KEY, current.why, None, warning)


# --- the dialog, the unlock and the save question ----------------------------------


def _ask(current: KeyRun, found: SessionCheck) -> None:
    """Under the dialog lock: the password dialog, then the unlock and the save."""
    if not record_unless_open(current, SHOWING):
        return
    answer = dialog.ask_password(current.ctx, found, current.volume, why=current.why)
    if answer.key is None:
        record_unless_open(current, NOT_ENTERED[answer.outcome])
        return
    with answer.key as key:  # the one owner of the typed key: cleared on every path
        if _unlock(current, key):
            _mount_and_save(current, key)


def _unlock(current: KeyRun, key: SecretBytes) -> bool:
    """True once this unit opened the mapping and recorded it (J001)."""
    with locks.volume_lock(current.ctx, current.lock_key, timeout=current.lock_wait()):
        decided = None if mapping_open(current) else _open_once(current, key)
    if decided is None:
        log.log(
            NOTICE,
            "%s was unlocked another way while its key dialog was open",
            current.volume.name,
            extra=current.fields(),
        )
        return False
    report(current, decided)
    return decided.state is VolumeState.MOUNTING


def _open_once(current: KeyRun, key: SecretBytes) -> Decided | None:
    """Under the volume lock: the mapping name ahead (DD-10), one open, its record."""
    write(current, _ahead_of(current))
    opened = bitlocker.open_with_secret(
        current.ctx, current.device, current.volume.uuid, key
    )
    if opened is UnlockOutcome.FAILED and mapping_open(current):
        write(current, _without_mapping)
        return None
    decided = _after_open(current, opened)
    write(current, decide(current, decided))
    return decided


def _ahead_of(current: KeyRun) -> Callable[[Record], None]:
    """DD-10: the mapping name and the key unit's identity before the open."""

    def apply(record: Record) -> None:
        record.mapping = own_mapping(current, save_pending=False)
        record.dialog = dialog_field(current.ctx, ENTERED)

    return apply


def _without_mapping(record: Record) -> None:
    record.mapping = None


def _after_open(current: KeyRun, opened: UnlockOutcome) -> Decided:
    if opened is UnlockOutcome.OPENED:
        opened_mapping = own_mapping(current, save_pending=True)
        return Decided(VolumeState.MOUNTING, None, UNLOCKED, mapping=opened_mapping)
    if opened is UnlockOutcome.REJECTED:
        return Decided(VolumeState.UNLOCK_FAILED, None, UNLOCK_FAILED)
    warning = OPEN_FAILED.format(name=current.volume.name)
    return Decided(VolumeState.MOUNT_FAILED, REASON_UNKNOWN, UNLOCK_FAILED, warning)


def _mount_and_save(current: KeyRun, key: SecretBytes) -> None:
    """Ask for the mount, then the save question; ``save_pending`` is cleared after."""
    saved: bool | None = None
    try:
        _request_mount(current)
        saved = _save(current, key)
    finally:
        # None: the unit is being stopped (SIGTERM) or failed; it was not saved.
        _settle_save(current, saved=bool(saved), stopping=saved is None)


def _request_mount(current: KeyRun) -> None:
    unit = registered_unit(current.device_path)
    try:
        result = systemd.request_reconcile(current.ctx, unit)
    except ToolError as error:
        log.warning(
            "%s: the mount could not be requested from %s: %s",
            current.volume.name,
            unit,
            error.detail,
            extra=current.fields(),
        )
        return
    log.info(
        "%s: mount requested from %s: %s",
        current.volume.name,
        unit,
        result,
        extra=current.fields(),
    )


def _save(current: KeyRun, key: SecretBytes) -> bool:
    """The save question (AC-072): True only after a Yes and a stored key."""
    ctx = current.ctx
    name = current.volume.name
    found = session.check(ctx, need_display=True, deadline=current.deadline)
    if found.verdict is not Verdict.DESKTOP:
        log.info(
            "%s: no Desktop Mode session for the save question",
            name,
            extra=current.fields(),
        )
        return False
    if current.remaining() < dialog.SAVE_TIMEOUT:
        log.warning(
            "%s: no time left for the save question", name, extra=current.fields()
        )
        return False
    if not dialog.ask_save(ctx, found, current.volume):
        return False
    try:
        keystore.store(ctx, current.volume.uuid, key)
    except (MounterError, OSError) as error:
        detail = error.detail if isinstance(error, MounterError) else error.strerror
        log.error("%s: the key was not saved: %s", name, detail, extra=current.fields())
        return False
    return True


def _settle_save(current: KeyRun, *, saved: bool, stopping: bool) -> None:
    """Record ``saved`` or ``not-saved`` and clear ``save_pending`` (best effort)."""
    outcome = SAVED if saved else NOT_SAVED
    wait = current.lock_wait()
    if stopping:
        wait = min(wait, STOPPING_LOCK_WAIT)

    def settled(record: Record) -> None:
        if record.mapping is not None:
            record.mapping = dict(record.mapping, save_pending=False)
        record.dialog = dialog_field(current.ctx, outcome)

    try:
        with locks.volume_lock(current.ctx, current.lock_key, timeout=wait):
            write(current, settled)
    except (MounterError, OSError) as error:
        log.error(
            "%s: the save question's outcome was not recorded: %s",
            current.volume.name,
            error,
            extra=current.fields(),
        )
    log.log(
        NOTICE,
        "%s: key %s",
        current.volume.name,
        "saved" if saved else "not saved",
        extra=current.fields(),
    )
