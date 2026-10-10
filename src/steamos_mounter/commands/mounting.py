"""``mount`` and ``unmount``: the owner asks systemd, or unmounts by hand.

Design Doc "CLI Contract > Commands" (``mount``, ``unmount``), D013, D014,
DD-11, DD-26 and "Locks"; ADR-0001 (the CLI never mounts itself: the
instance that owns the volume does, through ``systemctl``).

``mount``: the device must be attached (exit 7). ``--device`` on a device
``scan`` calls ineligible is refused with ``scan``'s reason (exit 8) from
lsblk alone, before any ``systemctl`` call (D013). The target instance is
the registered one for a registered volume (a mapping counts through its
container), else the auto instance of the physical partition. The
``cli_request`` marker goes into the owner's record under the volume lock,
which is released before ``systemctl start`` (inactive) or ``reload``
(running), blocking, 120 s. Only a reload needs the marker; with a start the
``start`` trigger already permits the key dialog (D014). The final line is
the volume's view: exit 0 when it is mounted, or when it needs a key and the
key dialog is open; 1 otherwise.

``unmount``: under the volume lock, a normal unmount (20 s) of the tool's
own mount; busy is exit 1, never a lazy unmount for an owner command. Then
the tool's own mapping is closed, the leaf it created removed, and the record
says ``UnmountedByUser`` for the device number that was mounted (the inner
mapping's for BitLocker, DD-11). The instance stays active.
"""

import argparse
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import UTC
from typing import TYPE_CHECKING, Any, Final

from steamos_mounter import (
    bitlocker,
    blockdev,
    locks,
    mounter,
    mounts,
    records,
    state,
    systemd,
)
from steamos_mounter import reconcile_report as report
from steamos_mounter.blockdev import BlockDevice, DeviceTree
from steamos_mounter.commands import Command, Invocation, devices, eligibility
from steamos_mounter.errors import (
    ExitCode,
    MounterError,
    NotPresentError,
    RefusedError,
    ToolError,
    UsageError,
)
from steamos_mounter.escape import BY_UUID_DIR
from steamos_mounter.journal import NOTICE, fields
from steamos_mounter.model import InstanceKind, Registry, Volume, VolumeState
from steamos_mounter.reconcile_report import Owner
from steamos_mounter.reconcile_unlock import key_unit_name
from steamos_mounter.records import TIMESTAMP_FORMAT, UNREADABLE, Record

if TYPE_CHECKING:
    from steamos_mounter.context import Context

MOUNT: Final = "mount"
UNMOUNT: Final = "unmount"
VERB_TIMEOUT: Final = 120.0
TOKEN_BYTES: Final = 8  # 16 hex digits
REASON_DIALOG_OPEN: Final = "dialog_open"
DIALOG_OPENED: Final = "{name}: key dialog opened. Answer it on the Deck's screen"
CLOSED_RESULTS: Final = frozenset({"closed", "absent"})
GONE_RESULTS: Final = frozenset({"unmounted", "absent"})
UNMOUNTED: Final = "unmounted"

log = logging.getLogger(__name__)


# --- arguments ------------------------------------------------------------------------


def configure_mount(parser: argparse.ArgumentParser) -> None:
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--volume", metavar="NAME", help="a registered volume")
    which.add_argument("--device", metavar="DEV", help="a device, e.g. /dev/sdc1")


def configure_unmount(parser: argparse.ArgumentParser) -> None:
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--volume", metavar="NAME", help="a registered volume")
    which.add_argument("--device", metavar="DEV", help="a device, e.g. /dev/sdc1")
    which.add_argument("--path", metavar="PATH", help="where it is mounted")


# --- mount ----------------------------------------------------------------------------


def run_mount(call: Invocation) -> ExitCode:
    ctx = call.ctx
    registry = devices.load_registry(ctx)
    facts = eligibility.gather(ctx, registry)
    owner = _mount_owner(call, facts, registry)
    _mark(ctx, owner)
    active = devices.active_state(ctx, owner.unit)
    verb = systemd.reload if active in devices.RUNNING_STATES else systemd.start
    result = verb(ctx, owner.unit, block=True, timeout=VERB_TIMEOUT)
    log.info(
        "%s: systemctl %s %s: exit %s",
        owner.name,
        verb.__name__,
        owner.unit,
        result.returncode,
        extra=fields(volume=owner.name, unit=owner.unit, event=MOUNT),
    )
    return _report(call, owner, registry)


def _mount_owner(
    call: Invocation, facts: eligibility.Facts, registry: Registry
) -> Owner:
    """The instance that mounts the volume ``--volume`` or ``--device`` names."""
    args = call.args
    if args.volume is not None:
        volume = devices.registered(registry, args.volume)
        present = facts.tree.by_uuid(volume.uuid)
        if not present:
            raise NotPresentError(f"{volume.name} is not plugged in")
        return devices.registered_owner(volume, present[0])
    device = devices.find_device(call.ctx, facts.tree, args.device)
    base = _base(device, facts.tree)
    volume = _registered_volume(registry, base)
    if volume is not None:
        return devices.registered_owner(volume, base)
    reason = eligibility.why_not_mountable(device, facts)
    if reason is not None:
        raise RefusedError(
            f"cannot mount {args.device}: {reason}",
            detail=f"mount refused /dev/{device.kname}: {reason}",
        )
    return devices.auto_owner(call.ctx, base)


def _base(device: BlockDevice, tree: DeviceTree) -> BlockDevice:
    """A mapping is served through the container it sits on (ADR-0001 CLI rules)."""
    if eligibility.is_mapping(device):
        return eligibility.container(device, tree) or device
    return device


def _registered_volume(registry: Registry, device: BlockDevice) -> Volume | None:
    return registry.by_uuid(device.uuid) if device.uuid is not None else None


def _mark(ctx: "Context", owner: Owner) -> None:
    """Write ``cli_request`` under the volume lock; the lock is released after.

    An unreadable record is left for teardown's fallback sweep, and an auto
    volume without a record has no instance state a marker could change.
    """
    with locks.volume_lock(ctx, owner.lock_key, timeout=devices.CLI_LOCK_WAIT):
        found = records.load_record(ctx, owner.kind, owner.key)
        if found == UNREADABLE or (found is None and owner.kind is InstanceKind.AUTO):
            log.warning("%s: no cli_request marker written", owner.name)
            return
        stamp = _stamp(ctx)
        token = secrets.token_hex(TOKEN_BYTES)

        def marked(record: Record) -> None:
            record.name = record.name or owner.name
            record.unit = record.unit or owner.unit
            record.cli_request = {"token": token, "at": stamp}

        records.update_record(ctx, owner.kind, owner.key, marked)


def _report(call: Invocation, owner: Owner, registry: Registry) -> ExitCode:
    """Read the view after systemd answered and print one line."""
    ctx = call.ctx
    view = _view(ctx, owner, registry)
    if view is None:
        call.out.line(f"{owner.name}: not mounted: steamos-mounter does not handle it")
        return ExitCode.FAILED
    words = state.words(view.state, view.reason)
    if view.state in state.OWN_MOUNT_STATES:
        call.out.line(f"{view.name}: {words} at {view.path}")
        return ExitCode.OK
    if view.state is VolumeState.NEEDS_KEY and _dialog_open(ctx, owner, view):
        call.out.line(DIALOG_OPENED.format(name=view.name))
        return ExitCode.OK
    call.out.line(f"{view.name}: {words}. {view.next_step}")
    return ExitCode.FAILED


def _view(ctx: "Context", owner: Owner, registry: Registry) -> state.VolumeView | None:
    tree = blockdev.read_tree(ctx)
    table = mounts.table(ctx)
    if owner.kind is InstanceKind.REGISTERED:
        volume = registry.by_uuid(owner.uuid)
        return (
            None if volume is None else state.registered_view(ctx, volume, tree, table)
        )
    found = records.load_record(ctx, owner.kind, owner.key)
    if not isinstance(found, Record):
        return None
    return state.auto_view(ctx, found, tree, table)


def _dialog_open(ctx: "Context", owner: Owner, view: state.VolumeView) -> bool:
    """The record says so, or the registered volume's key unit runs (AC-075)."""
    if view.reason == REASON_DIALOG_OPEN:
        return True
    key_unit = key_unit_name(BY_UUID_DIR + owner.uuid)
    return owner.kind is InstanceKind.REGISTERED and (
        devices.active_state(ctx, key_unit) in devices.RUNNING_STATES
    )


# --- unmount --------------------------------------------------------------------------


@dataclass(slots=True)
class _Unmounted:
    """What the locked part did, for the record and the output."""

    target: str | None = None
    closed: str | None = None
    close_failed: str | None = None
    created_dir: bool = False


def run_unmount(call: Invocation) -> ExitCode:
    ctx = call.ctx
    registry = devices.load_registry(ctx)
    tree = blockdev.read_tree(ctx)
    owner = _unmount_owner(call, registry, tree)
    with locks.volume_lock(ctx, owner.lock_key, timeout=devices.CLI_LOCK_WAIT):
        record = _owned_record(ctx, owner)
        done = _Unmounted() if record is None else _undo(ctx, owner, record)
        if record is not None and (done.target or done.closed):
            _record_unmounted(ctx, owner, record, done)
    return _unmount_report(call, owner, done)


def _unmount_owner(call: Invocation, registry: Registry, tree: DeviceTree) -> Owner:
    args = call.args
    if args.volume is not None:
        return _present_volume(registry, tree, args.volume)
    if args.path is not None:
        return _owner_at(call.ctx, registry, tree, args.path)
    base = _base(devices.find_device(call.ctx, tree, args.device), tree)
    volume = _registered_volume(registry, base)
    if volume is not None:
        return devices.registered_owner(volume, base)
    owner = devices.auto_owner(call.ctx, base)
    if records.load_record(call.ctx, owner.kind, owner.key) is None:
        raise UsageError(f"steamos-mounter has not mounted {args.device}")
    return owner


def _present_volume(registry: Registry, tree: DeviceTree, name: str) -> Owner:
    volume = devices.registered(registry, name)
    present = tree.by_uuid(volume.uuid)
    if not present:
        raise NotPresentError(f"{volume.name} is not plugged in")
    return devices.registered_owner(volume, present[0])


def _owner_at(ctx: "Context", registry: Registry, tree: DeviceTree, path: str) -> Owner:
    """The registered volume with fixed path ``path``, or the auto record there."""
    for volume in registry.volumes:
        if volume.path == path:
            return _present_volume(registry, tree, volume.name)
    for record in state.auto_records(ctx):
        if records.own_mount_target(record) == path:
            return _auto_record_owner(ctx, tree, record)
    raise UsageError(f"steamos-mounter has no volume mounted at {path}")


def _auto_record_owner(ctx: "Context", tree: DeviceTree, record: Record) -> Owner:
    source = record.source or {}
    device = tree.devices.get(str(source.get("kname")))
    if device is None or device.devnum != source.get("devnum"):
        raise NotPresentError(f"{record.name} is not plugged in")
    return devices.auto_owner(ctx, device)


def _owned_record(ctx: "Context", owner: Owner) -> Record | None:
    found = records.load_record(ctx, owner.kind, owner.key)
    if found == UNREADABLE:
        raise MounterError(
            f"the state record of {owner.name} is unreadable. Run "
            f"{ctx.platform.cli_root} doctor",
            detail=f"record {owner.kind}/{owner.key} unreadable",
        )
    return found if isinstance(found, Record) else None


def _undo(ctx: "Context", owner: Owner, record: Record) -> _Unmounted:
    """The normal unmount, then the tool's own mapping; never lazy, never deferred."""
    done = _Unmounted()
    target = records.own_mount_target(record)
    if target is not None:
        result = mounter.unmount(
            ctx, target, mode="normal", timeout=mounter.NORMAL_UNMOUNT_TIMEOUT
        )
        if result.result == "busy":
            raise MounterError(
                f"{target} is busy. Close the files open on {target} and try again",
                detail=f"umount {target}: {result.detail}",
            )
        if result.result not in GONE_RESULTS:
            raise ToolError(
                f"{owner.name} could not be unmounted",
                detail=f"umount {target}: {result.detail}",
            )
        done.target = target
        done.created_dir = bool((record.mount or {}).get("created_dir"))
    _close_mapping(ctx, record.mapping, done)
    return done


def _close_mapping(
    ctx: "Context", mapping: dict[str, Any] | None, done: _Unmounted
) -> None:
    name = (mapping or {}).get("name")
    if not isinstance(name, str) or not bitlocker.is_tool_mapping(name):
        return  # none, or Dolphin's: left alone (AC-060)
    uuid = name.removeprefix(bitlocker.MAPPING_PREFIX)
    result = bitlocker.close_own(ctx, uuid, deferred=False)
    if result in CLOSED_RESULTS:
        done.closed = name
    else:
        done.close_failed = name


def _record_unmounted(
    ctx: "Context", owner: Owner, record: Record, done: _Unmounted
) -> None:
    """``UnmountedByUser`` for the mounted device number (DD-11), leaf removed."""
    if done.target is not None and done.created_dir:
        _remove_leaf(ctx, done.target)
    stamp = _stamp(ctx)
    devnum = _mounted_devnum(record)
    step = report.next_step(ctx, owner, VolumeState.UNMOUNTED_BY_USER, None)

    def change(saved: Record) -> None:
        saved.state = VolumeState.UNMOUNTED_BY_USER
        saved.reason = None
        saved.warning = None
        saved.next_step = step
        saved.unmounted_by_user = {"devnum": devnum, "at": stamp}
        if saved.mount is not None and done.target is not None:
            saved.mount = dict(saved.mount, status=UNMOUNTED)
        if done.closed is not None:
            saved.mapping = None

    records.update_record(ctx, owner.kind, owner.key, change)
    log.log(
        NOTICE,
        "%s unmounted by the user",
        owner.name,
        extra=fields(
            volume=owner.name,
            uuid=owner.uuid or None,
            event=UNMOUNT,
            state=VolumeState.UNMOUNTED_BY_USER.value,
        ),
    )


def _mounted_devnum(record: Record) -> str | None:
    """The device that was mounted: the inner mapping for BitLocker (DD-11)."""
    parts = (record.mount, record.mapping, record.source)
    found = ((part or {}).get("devnum") for part in parts)
    return next((devnum for devnum in found if isinstance(devnum, str)), None)


def _stamp(ctx: "Context") -> str:
    return ctx.clock.now().astimezone(UTC).strftime(TIMESTAMP_FORMAT)


def _remove_leaf(ctx: "Context", target: str) -> None:
    """DD-26: only the leaf the tool created, and only when it is empty."""
    try:
        os.rmdir(ctx.paths.p(target))
    except OSError as error:
        log.warning("%s was not removed: %s", target, error.strerror)


def _unmount_report(call: Invocation, owner: Owner, done: _Unmounted) -> ExitCode:
    out = call.out
    if done.target is None and done.closed is None and done.close_failed is None:
        out.line(f"{owner.name}: not mounted by steamos-mounter")
        return ExitCode.OK
    if done.target is not None:
        out.line(f"unmounted {owner.name} from {done.target}")
    if done.closed is not None:
        out.line(f"closed {done.closed}")
    if done.close_failed is not None:
        raise ToolError(
            f"{owner.name} is unmounted, but its unlocked mapping could not be closed",
            detail=f"cryptsetup close {done.close_failed} failed",
        )
    return ExitCode.OK


COMMANDS: Final = (
    Command(
        name=MOUNT,
        summary="mount a volume now, through its systemd instance",
        root_only=True,
        exit_codes=frozenset(
            {
                ExitCode.OK,
                ExitCode.FAILED,
                ExitCode.USAGE,
                ExitCode.NEEDS_ROOT,
                ExitCode.UNSUPPORTED_PLATFORM,
                ExitCode.NOT_PRESENT,
                ExitCode.REFUSED,
            }
        ),
        configure=configure_mount,
        run=run_mount,
    ),
    Command(
        name=UNMOUNT,
        summary="unmount a volume and close its mapping; it stays unmounted",
        root_only=True,
        exit_codes=frozenset(
            {
                ExitCode.OK,
                ExitCode.FAILED,
                ExitCode.USAGE,
                ExitCode.NEEDS_ROOT,
                ExitCode.UNSUPPORTED_PLATFORM,
                ExitCode.NOT_PRESENT,
            }
        ),
        configure=configure_unmount,
        run=run_unmount,
    ),
)
