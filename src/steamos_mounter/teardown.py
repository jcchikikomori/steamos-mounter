"""The ``ExecStop=`` and ``ExecStopPost=`` bodies: one idempotent teardown.

Design Doc "Teardown" (flowchart and items 1 to 5), "Unplug Teardown",
"BitLocker Unlock and Mappings" (DD-15), "Locks" (I007), "Runtime State
Records" and the EARS block "Records and Teardown"; ADR-0001 Decision 3 and
guidance 8 to 10, ADR-0004 D5.

- ``stop`` and ``sweep`` run the same routine under the per-volume lock. The
  sweep also logs the service result (ERROR unless ``success``), stores it
  in the record, and deletes an auto record after an unplug.
- The record decides. Missing: the instance owns nothing. Unreadable: the
  fallback sweep (registered: the registry path and the tool mapping name;
  auto: the mounts of ``/dev/<kname>``), recorded with reason
  ``record_unreadable``. Readable: the recorded target and mapping.
- Unplug or deliberate stop: ``/sys/dev/block/<recorded devnum>`` no longer
  resolving to the recorded syspath means the device is gone. Unplug: lazy
  unmount, then every mapping stacked on the recorded device number
  (``dmsetup deps`` per ``/sys/block/dm-*``, never sysfs ``holders/``)
  closed with ``--deferred``, the tool's own by name and foreign ones by
  device number only. Deliberate stop: normal unmount (20 s), lazy when busy;
  the tool's own mapping closed normally, ``--deferred`` when busy; foreign
  mappings stay. ``busy`` lists the lazy and deferred cases of a deliberate
  stop and whatever could not be undone.
- Idempotent: a done target is ``unmounted`` in the record, a closed mapping
  is gone from it, and a finished unplug (``NotPresent``, nothing busy) does
  not look for stacked mappings again.
- Split by step: ``teardown_report`` holds the report types, the final
  record write and the journal entries; ``TeardownReport`` and
  ``ServiceResult`` are re-exported here, the names the Design Doc gives.
- Auto lock key (I007): the filesystem UUID from ``/dev/disk/by-uuid`` while
  the device is there; after an unplug those links are gone and the record
  holds no UUID, so the record key is used.
"""

import logging
import os
import re
from typing import TYPE_CHECKING, Any, Final

from steamos_mounter import bitlocker, blockdev, config, locks, mounter, mounts
from steamos_mounter.errors import RegistryError, ToolError
from steamos_mounter.escape import BY_UUID_DIR
from steamos_mounter.journal import fields
from steamos_mounter.locks import VOLUME_KEY
from steamos_mounter.model import InstanceKind, VolumeState
from steamos_mounter.mounter import UnmountResult
from steamos_mounter.records import (
    RECORD_SUFFIX,
    RECORDS_DIR,
    Record,
    delete_record,
    load_record,
    update_record,
)
from steamos_mounter.teardown_report import (
    Change,
    Instance,
    Work,
    journal,
    log_service,
    owner_for,
    owns_nothing,
    settle,
    with_service,
)
from steamos_mounter.teardown_report import ServiceResult as ServiceResult
from steamos_mounter.teardown_report import TeardownReport as TeardownReport

if TYPE_CHECKING:
    from steamos_mounter.context import Context

LOCK_WAIT: Final = 10.0  # TimeoutStopSec=60 minus 20 + 10 + 10 + 10 s of tools
REASON_RECORD_UNREADABLE: Final = "record_unreadable"
UNMOUNTED: Final = "unmounted"
OWN_STATUSES: Final = frozenset({"pending", "mounted"})
GONE_RESULTS: Final = frozenset({"unmounted", "lazy", "absent"})
DONE_CLOSES: Final = frozenset({"closed", "absent"})
_SYS_DEV_BLOCK: Final = "/sys/dev/block"
_DEVNUM: Final = re.compile(r"\d+:\d+")

log = logging.getLogger(__name__)


def stop(ctx: "Context", kind: InstanceKind, device_path: str) -> TeardownReport:
    """``ExecStop=``: tear down what this instance's record says it owns.

    Raises ``LockTimeout`` when the volume lock stays held; the sweep that
    follows runs the same routine again.
    """
    return _run(ctx, InstanceKind(kind), device_path, None)


def sweep(
    ctx: "Context", kind: InstanceKind, device_path: str, svc: ServiceResult
) -> TeardownReport:
    """``ExecStopPost=``: the same routine, plus the service result."""
    return _run(ctx, InstanceKind(kind), device_path, svc)


def _run(
    ctx: "Context", kind: InstanceKind, device_path: str, svc: ServiceResult | None
) -> TeardownReport:
    instance = _locate(ctx, kind, device_path)
    if instance is None:
        return owns_nothing(device_path, svc)
    with locks.volume_lock(ctx, instance.lock_key, timeout=LOCK_WAIT):
        found = load_record(ctx, kind, instance.key)
        if found is None:
            return owns_nothing(device_path, svc)
        if isinstance(found, Record):
            work, change = _recorded(ctx, instance, found)
        else:
            work, change = _fallback(ctx, instance)
        record = update_record(ctx, kind, instance.key, with_service(ctx, change, svc))
        if svc is not None:
            log_service(instance, record, svc)
            if kind is InstanceKind.AUTO and work.unplugged:
                delete_record(ctx, kind, instance.key)
    report = work.report()
    journal(instance, record, report, svc)
    return report


# --- which record --------------------------------------------------------------------


def _locate(ctx: "Context", kind: InstanceKind, device_path: str) -> Instance | None:
    tail = device_path.rpartition("/")[2]
    if kind is InstanceKind.REGISTERED:
        key = tail.lower()
        return Instance(kind, device_path, key, key, tail)
    kname = blockdev.kname_of_syspath(device_path)
    key = _auto_key(ctx, kname, device_path)
    if key is None:
        return None
    return Instance(kind, device_path, key, _auto_lock_key(ctx, kname, key), kname)


def _auto_key(ctx: "Context", kname: str, device_path: str) -> str | None:
    """``<kname>-<major>_<minor>`` of this instance's record, found without sysfs.

    At unplug the device number can no longer be read, so the records of
    ``kname`` are matched by their recorded syspath; an unreadable one cannot
    tell and is taken when no readable one matches.
    """
    pattern = re.compile(re.escape(kname) + r"-\d+_\d+")
    try:
        names = sorted(os.listdir(ctx.paths.p(f"{RECORDS_DIR}/{InstanceKind.AUTO}")))
    except FileNotFoundError:
        return None
    keys = [
        name.removesuffix(RECORD_SUFFIX)
        for name in names
        if name.endswith(RECORD_SUFFIX)
        and pattern.fullmatch(name.removesuffix(RECORD_SUFFIX))
    ]
    unreadable = None
    for key in keys:
        found = load_record(ctx, InstanceKind.AUTO, key)
        if isinstance(found, Record):
            if (found.source or {}).get("syspath") == device_path:
                return key
        elif unreadable is None:
            unreadable = key
    return unreadable


def _auto_lock_key(ctx: "Context", kname: str, record_key: str) -> str:
    directory = ctx.paths.p(BY_UUID_DIR)
    device = os.path.realpath(ctx.paths.p(f"/dev/{kname}"))
    try:
        names = sorted(os.listdir(directory))
    except FileNotFoundError:
        return record_key
    for name in names:
        lowered = name.lower()
        if VOLUME_KEY.fullmatch(lowered) and (
            os.path.realpath(directory / name) == device
        ):
            return lowered
    return record_key


# --- a readable record ---------------------------------------------------------------


def _recorded(
    ctx: "Context", instance: Instance, record: Record
) -> tuple[Work, Change]:
    source = record.source or {}
    gone = _vanished_devnum(ctx, source)
    work = Work(unplugged=gone is not None)
    mount = record.mount or {}
    target = mount.get("target") if mount.get("status") in OWN_STATUSES else None
    left_mounted = False
    if isinstance(target, str):
        left_mounted = not _unmount(ctx, target, work)
        if not left_mounted and mount.get("created_dir"):
            _remove_leaf(ctx, target)
    if gone is None:
        mapping_done = _close_own(ctx, record.mapping, work)
    elif record.state is VolumeState.NOT_PRESENT and not record.busy:
        mapping_done = True  # an earlier run finished this unplug
    else:
        mapping_done = _close_stacked(ctx, gone, work)
    owner = owner_for(instance, record.name, source.get("kname"))

    def change(saved: Record) -> None:
        settle(ctx, owner, saved, work, None)
        if saved.mount is not None and not left_mounted:
            saved.mount = dict(saved.mount, status=UNMOUNTED)
        if mapping_done:
            saved.mapping = None

    return work, change


def _vanished_devnum(ctx: "Context", source: dict[str, Any]) -> str | None:
    """The recorded device number once it names no device, or another one.

    None while the recorded device is there. A record without a usable
    device number cannot tell an unplug, so it is torn down as a deliberate
    stop, which never touches foreign mappings.
    """
    devnum = source.get("devnum")
    if not isinstance(devnum, str) or _DEVNUM.fullmatch(devnum) is None:
        return None
    link = ctx.paths.p(f"{_SYS_DEV_BLOCK}/{devnum}")
    if not link.exists():
        return devnum
    recorded = source.get("syspath")
    if not isinstance(recorded, str):
        return None
    root = ctx.paths.root.resolve()
    resolved = link.resolve()
    if resolved.is_relative_to(root) and (
        "/" + resolved.relative_to(root).as_posix() == recorded
    ):
        return None
    return devnum


def _unmount(ctx: "Context", target: str, work: Work) -> bool:
    """Unmount ``target``; False when it is still mounted."""
    if work.unplugged:
        mode, timeout = "lazy", mounter.LAZY_UNMOUNT_TIMEOUT
    else:
        mode, timeout = "normal-then-lazy", mounter.NORMAL_UNMOUNT_TIMEOUT
    try:
        result = mounter.unmount(ctx, target, mode=mode, timeout=timeout)
    except ToolError as error:
        log.error("cannot tell whether %s is mounted: %s", target, error.detail)
        result = UnmountResult(target, "failed", error.detail)
    work.unmounts.append(result)
    gone = result.result in GONE_RESULTS
    if not gone or (result.result == "lazy" and not work.unplugged):
        work.busy.append(target)
    return gone


def _remove_leaf(ctx: "Context", target: str) -> None:
    """DD-26: remove only the leaf this tool created, and only when empty."""
    try:
        os.rmdir(ctx.paths.p(target))
    except FileNotFoundError:
        return
    except OSError as error:
        log.warning("%s was not removed: %s", target, error.strerror)
        return
    log.info("removed the mount directory %s", target)


def _own_uuid(name: str | None) -> str | None:
    """The UUID in a tool mapping name; None for any other name."""
    if name is None or not bitlocker.is_tool_mapping(name):
        return None
    uuid = name.removeprefix(bitlocker.MAPPING_PREFIX)
    try:
        bitlocker.mapping_name(uuid)
    except ValueError:
        return None
    return uuid


def _close_own(ctx: "Context", mapping: dict[str, Any] | None, work: Work) -> bool:
    """Deliberate stop: close the tool's mapping, ``--deferred`` only when busy.

    Returns True when the record no longer has a mapping to keep.
    """
    if mapping is None:
        return True
    name = mapping.get("name")
    uuid = _own_uuid(name if isinstance(name, str) else None)
    if uuid is None:
        return False  # foreign (Dolphin's): left alone
    return _close_by_name(ctx, uuid, work, deferred=False)


def _close_by_name(ctx: "Context", uuid: str, work: Work, *, deferred: bool) -> bool:
    name = bitlocker.mapping_name(uuid)
    result = bitlocker.close_own(ctx, uuid, deferred=deferred)
    if result == "busy" and not deferred:
        work.busy.append(name)
        result = bitlocker.close_own(ctx, uuid, deferred=True)
    elif result not in DONE_CLOSES:
        work.busy.append(name)
    if result == "closed":
        work.closes.append(name)
    return result in DONE_CLOSES


def _close_stacked(ctx: "Context", devnum: str, work: Work) -> bool:
    """Unplug: every mapping stacked on ``devnum``, foreign ones by number (DD-15)."""
    done = True
    for dm_devnum, name in bitlocker.mappings_stacked_on(ctx, (devnum,)):
        uuid = _own_uuid(name)
        if uuid is not None:
            done = _close_by_name(ctx, uuid, work, deferred=True) and done
            continue
        label = name or dm_devnum
        if bitlocker.remove_by_devnum(ctx, dm_devnum) == "removed":
            work.closes.append(label)
        else:
            work.busy.append(label)
            done = False
    return done


# --- an unreadable record: the fallback sweep (ADR-0004 D5) -------------------------


def _fallback(ctx: "Context", instance: Instance) -> tuple[Work, Change]:
    present = os.path.lexists(ctx.paths.p(instance.device_path))
    work = Work(unplugged=not present)
    uuid = None
    if instance.kind is InstanceKind.REGISTERED:
        name, targets, uuid = _registered_fallback(ctx, instance)
    else:
        name, targets = instance.tail, _device_targets(ctx, instance)
    log.warning(
        "%s: the record is unreadable: running the fallback sweep",
        name,
        extra=fields(volume=name, reason=REASON_RECORD_UNREADABLE),
    )
    for target in targets:
        _unmount(ctx, target, work)
    if uuid is not None:
        _close_by_name(ctx, uuid, work, deferred=work.unplugged)
    owner = owner_for(instance, name, None)

    def change(saved: Record) -> None:
        saved.name = name
        saved.unit = instance.unit()
        saved.invocation_id = ctx.invocation_id or ""
        settle(ctx, owner, saved, work, REASON_RECORD_UNREADABLE)

    return work, change


def _registered_fallback(
    ctx: "Context", instance: Instance
) -> tuple[str, tuple[str, ...], str | None]:
    """Name, fixed path and mapping UUID; the registry's when it has the volume.

    Without the registry entry the UUID of ``%f`` names the tool mapping,
    and nothing is unmounted. The UUID is None when it is not a registry
    UUID, so no mapping name can be built from it.
    """
    try:
        volume = config.load(ctx).by_uuid(instance.tail)
    except RegistryError as error:
        log.warning("fallback sweep without the registry: %s", error.detail)
        volume = None
    if volume is not None:
        return volume.name, (volume.path,), volume.uuid
    uuid = _own_uuid(bitlocker.MAPPING_PREFIX + instance.tail)
    return instance.tail, (), uuid


def _device_targets(ctx: "Context", instance: Instance) -> tuple[str, ...]:
    """Mount points of ``/dev/<kname>`` (or its device number), topmost first."""
    kname = instance.tail
    devnum = instance.key.removeprefix(f"{kname}-").replace("_", ":")
    try:
        table = mounts.table(ctx)
    except ToolError as error:
        log.error("fallback sweep of /dev/%s: %s", kname, error.detail)
        return ()
    rows = [
        row
        for row in table
        if row.devnum == devnum
        or mounts.canonical_source(row.source) == f"/dev/{kname}"
    ]
    return tuple(row.target for row in reversed(rows))
