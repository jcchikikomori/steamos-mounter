"""What ``list`` shows: the state views, state words and next steps.

Design Doc "Runtime State Records", "State Transitions", "list and scan
Output", DD-22 and I006. The ``/run`` tree and the records themselves live in
``records``.

- **Views**: ``findmnt`` is the truth for driver, mode and "mounted at all"
  (AC-063); the record adds what ``findmnt`` cannot know. A record that says
  mounted while nothing is mounted becomes ``UnmountedByUser`` while the
  device is present (the instance is bound to its device, so a present device
  means a live instance) and ``NotPresent`` once it is gone. A mount at a
  registered fixed path that the record does not own (no ``pending`` or
  ``mounted`` record mount at that target) is ``MountedElsewhere`` at that
  path: ``list`` never claims a mount the tool did not make. An unreadable
  record cannot disown it, so findmnt decides then. ``list`` never writes.
- **Words and next steps**: one table each, keyed by state and reason code;
  ``{cli}`` is the platform's ``cli_root`` (DD-05). Reason codes this module
  does not know render the state's default words and step.
"""

import os
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from steamos_mounter.blockdev import BlockDevice, DeviceTree
from steamos_mounter.errors import RegistryError
from steamos_mounter.locks import VOLUME_KEY
from steamos_mounter.model import (
    InstanceKind,
    MountInfo,
    Registry,
    Volume,
    VolumeState,
)
from steamos_mounter.mounts import for_device
from steamos_mounter.records import (
    RECORD_SUFFIX,
    RECORDS_DIR,
    UNREADABLE,
    Record,
    load_record,
    own_mount_target,
)

if TYPE_CHECKING:
    from steamos_mounter.context import Context

NO_NEXT_STEP: Final = "-"
FUSE_FSTYPE: Final = "fuseblk"
FUSE_DRIVER: Final = "ntfs-3g"
CRYPT_TYPE: Final = "crypt"
READ_ONLY: Final = "ro"
READ_WRITE: Final = "rw"
UNSAFE_STATE: Final = "unsafe state (hibernation, Fast Startup, or an abrupt unplug)"

# States in which this tool's own mount should be in findmnt.
OWN_MOUNT_STATES: Final = frozenset(
    {VolumeState.MOUNTED_RW, VolumeState.MOUNTED_RW_DIRTY, VolumeState.MOUNTED_RO}
)
# Record states that say nothing about a present device with no mount.
STALE_WHEN_UNMOUNTED: Final = frozenset(
    {VolumeState.NOT_PRESENT, VolumeState.MOUNTED_ELSEWHERE}
)

_KEY_DEVNUM_SEPARATOR: Final = "-"


# --- views (list) ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VolumeView:
    name: str
    uuid: str
    kind: InstanceKind
    present: bool | None
    path: str | None
    driver: str | None
    mode: str | None
    state: VolumeState
    reason: str | None
    warning: str | None
    next_step: str


@dataclass(frozen=True, slots=True)
class _Facts:
    """What lsblk and the registry or record say about one volume."""

    name: str
    uuid: str
    kind: InstanceKind
    present: bool
    target: str | None
    owned_target: str | None  # where the tool's own mount is, per the record
    devices: tuple[BlockDevice, ...]


def compute_views(
    ctx: "Context",
    registry: Registry | RegistryError,
    tree: DeviceTree,
    table: Sequence[MountInfo],
) -> list[VolumeView]:
    """Registered volumes sorted by name, then auto volumes sorted by path.

    An unusable registry gives no registered rows. Auto rows come from the
    readable auto records; an unreadable one is skipped. Nothing is written.
    """
    registered: list[VolumeView] = []
    if not isinstance(registry, RegistryError):
        registered = [
            registered_view(ctx, volume, tree, table)
            for volume in sorted(registry.volumes, key=_volume_name)
        ]
    auto = [auto_view(ctx, record, tree, table) for record in auto_records(ctx)]
    return registered + sorted(auto, key=_view_path)


def _volume_name(volume: Volume) -> str:
    return volume.name


def _view_path(view: VolumeView) -> tuple[str, str]:
    return (view.path or "", view.name)


def registered_view(
    ctx: "Context", volume: Volume, tree: DeviceTree, table: Sequence[MountInfo]
) -> VolumeView:
    """The view of one registered volume (``list``, ``mount``'s final line)."""
    devices = tree.by_uuid(volume.uuid)
    found = load_record(ctx, InstanceKind.REGISTERED, volume.uuid)
    record = found if isinstance(found, Record) else None
    facts = _Facts(
        name=volume.name,
        uuid=volume.uuid,
        kind=InstanceKind.REGISTERED,
        present=bool(devices),
        target=volume.path,
        owned_target=volume.path if found == UNREADABLE else own_mount_target(record),
        devices=_with_mappings(tree, devices),
    )
    return _view(ctx, facts, record, table)


def auto_view(
    ctx: "Context", record: Record, tree: DeviceTree, table: Sequence[MountInfo]
) -> VolumeView:
    """The view of the auto volume ``record`` belongs to."""
    kname, _, devnum = record.key.rpartition(_KEY_DEVNUM_SEPARATOR)
    device = tree.devices.get(kname)
    present = device is not None and device.devnum == devnum.replace("_", ":")
    target = record.mount.get("target") if record.mount else None
    target = target if isinstance(target, str) else None
    facts = _Facts(
        name=record.name,
        uuid=(device.uuid or "") if device is not None and present else "",
        kind=InstanceKind.AUTO,
        present=present,
        target=target,
        owned_target=target,  # an auto path exists only through its record
        devices=_with_mappings(tree, (device,))
        if device is not None and present
        else (),
    )
    return _view(ctx, facts, record, table)


def auto_records(ctx: "Context") -> Iterator[Record]:
    """Every readable auto record, by file name; unreadable ones are skipped."""
    directory = ctx.paths.p(f"{RECORDS_DIR}/{InstanceKind.AUTO.value}")
    try:
        names = sorted(os.listdir(directory))
    except (FileNotFoundError, NotADirectoryError):
        return
    for name in names:
        key = name.removesuffix(RECORD_SUFFIX)
        if key == name or VOLUME_KEY.fullmatch(key) is None:
            continue
        record = load_record(ctx, InstanceKind.AUTO, key)
        if isinstance(record, Record):
            yield record


def _with_mappings(
    tree: DeviceTree, devices: Sequence[BlockDevice]
) -> tuple[BlockDevice, ...]:
    """``devices`` and the crypt mappings stacked directly on them."""
    knames = {device.kname for device in devices}
    mappings = [
        tree.devices[kname]
        for kname, parents in tree.parents.items()
        if knames.intersection(parents) and tree.devices[kname].type == CRYPT_TYPE
    ]
    return (*devices, *mappings)


def _view(
    ctx: "Context",
    facts: _Facts,
    record: Record | None,
    table: Sequence[MountInfo],
) -> VolumeView:
    at_target = [info for info in table if facts.target and info.target == facts.target]
    if at_target:
        mount = at_target[-1]
        if facts.owned_target != facts.target:
            return _build(ctx, facts, record, VolumeState.MOUNTED_ELSEWHERE, mount)
        if mount.read_only:
            mounted_state = VolumeState.MOUNTED_RO
        elif record is not None and record.state is VolumeState.MOUNTED_RW_DIRTY:
            mounted_state = VolumeState.MOUNTED_RW_DIRTY
        else:
            mounted_state = VolumeState.MOUNTED_RW
        return _build(ctx, facts, record, mounted_state, mount)
    elsewhere = _mounted_elsewhere(facts, table)
    if elsewhere is not None:
        return _build(ctx, facts, record, VolumeState.MOUNTED_ELSEWHERE, elsewhere)
    if not facts.present:
        return _build(ctx, facts, None, VolumeState.NOT_PRESENT, None)
    if record is None or record.state in STALE_WHEN_UNMOUNTED:
        return _build(ctx, facts, None, VolumeState.NOT_MOUNTED, None)
    if record.state in OWN_MOUNT_STATES:
        return _build(ctx, facts, None, VolumeState.UNMOUNTED_BY_USER, None)
    return _build(ctx, facts, record, record.state, None)


def _mounted_elsewhere(facts: _Facts, table: Sequence[MountInfo]) -> MountInfo | None:
    """The first mount of the volume's devices; called once none is at the target."""
    for device in facts.devices:
        found = for_device(table, device, None)
        if found:
            return found[0]
    return None


def _build(
    ctx: "Context",
    facts: _Facts,
    record: Record | None,
    volume_state: VolumeState,
    mount: MountInfo | None,
) -> VolumeView:
    """The view; the record's words count only when it reports this state."""
    own = record if record is not None and record.state is volume_state else None
    reason = own.reason if own is not None else None
    default_step = next_step(
        volume_state, reason, name=facts.name, cli_root=ctx.platform.cli_root
    )
    return VolumeView(
        name=facts.name,
        uuid=facts.uuid,
        kind=facts.kind,
        present=facts.present,
        path=mount.target if mount is not None else facts.target,
        driver=_driver(mount),
        mode=None if mount is None else READ_ONLY if mount.read_only else READ_WRITE,
        state=volume_state,
        reason=reason,
        warning=own.warning if own is not None else None,
        next_step=(own.next_step if own is not None else None) or default_step,
    )


def _driver(mount: MountInfo | None) -> str | None:
    if mount is None:
        return None
    return FUSE_DRIVER if mount.fstype == FUSE_FSTYPE else mount.fstype


# --- words, next steps and warnings ---------------------------------------------------

# Reason codes, per state, that the components record (Design Doc: Routing,
# UNLOCK_REGISTERED executor, Key Dialog Unit, Read-back and State, Locks,
# Names and Paths, I006, and teardown's fallback sweep for an unreadable
# record). A known code without its own entry below uses the state's default
# words or step.
KNOWN_REASONS: Final[Mapping[VolumeState, frozenset[str]]] = MappingProxyType(
    {
        VolumeState.NOT_PRESENT: frozenset({"record_unreadable"}),
        VolumeState.NOT_MOUNTED: frozenset(
            {"no_partition_instance", "record_unreadable"}
        ),
        VolumeState.NEEDS_KEY: frozenset(
            {
                "stored_key_missing",
                "stored_key_rejected",
                "no_session",
                "session_not_sure",
                "dialog_open",
                "dialog_failed",
                "key_permissions",
            }
        ),
        VolumeState.UNLOCK_CANCELLED: frozenset(
            {"dialog_cancelled", "dialog_timed_out"}
        ),
        VolumeState.MOUNTED_RW_DIRTY: frozenset({"dirty"}),
        VolumeState.MOUNTED_RO: frozenset({"unsafe"}),
        VolumeState.MOUNTED_ELSEWHERE: frozenset({"held"}),
        VolumeState.MOUNT_FAILED: frozenset(
            {
                "fstype_mismatch",
                "device_busy",
                "no_free_name",
                "probe_failed",
                "registry_entry_invalid",
                "os_partition",
                "unknown",
                "internal_error",  # the top-level catch of a unit (Internal Verbs)
            }
        ),
    }
)

_WORDS: Final[Mapping[VolumeState, str]] = MappingProxyType(
    {
        VolumeState.NOT_PRESENT: "not present",
        VolumeState.NOT_MOUNTED: "present, not mounted yet",
        VolumeState.LOCKED: "locked and skipped",
        VolumeState.NEEDS_KEY: "needs a key",
        VolumeState.UNLOCK_FAILED: "unlock failed",
        VolumeState.UNLOCK_CANCELLED: "unlock cancelled at the key dialog",
        VolumeState.MOUNTING: "mounting",
        VolumeState.MOUNTED_RW: "mounted read-write",
        VolumeState.MOUNTED_RW_DIRTY: "mounted read-write via ntfs-3g (dirty)",
        VolumeState.MOUNTED_RO: "mounted read-only",
        # The renderer adds "(at PATH)" from the view's path.
        VolumeState.MOUNTED_ELSEWHERE: "mounted elsewhere",
        VolumeState.MOUNT_FAILED: "mount failed",
        VolumeState.MOUNT_TIMED_OUT: "mount timed out",
        VolumeState.UNMOUNTED_BY_USER: "unmounted by the user",
    }
)
_RECORD_UNREADABLE: Final = "its state record was unreadable"
_REASON_WORDS: Final[Mapping[tuple[VolumeState, str], str]] = MappingProxyType(
    {
        (VolumeState.NOT_PRESENT, "record_unreadable"): _RECORD_UNREADABLE,
        (VolumeState.NOT_MOUNTED, "record_unreadable"): _RECORD_UNREADABLE,
        (VolumeState.NEEDS_KEY, "dialog_open"): "key dialog open",
        (VolumeState.NEEDS_KEY, "dialog_failed"): "key dialog could not be shown",
        (VolumeState.NEEDS_KEY, "key_permissions"): "key file permissions",
        (VolumeState.UNLOCK_CANCELLED, "dialog_timed_out"): "key dialog timed out",
        (VolumeState.MOUNTED_RO, "unsafe"): UNSAFE_STATE,
        (VolumeState.MOUNTED_ELSEWHERE, "held"): "held by another device",
        (VolumeState.MOUNT_FAILED, "fstype_mismatch"): "filesystem type changed",
        (VolumeState.MOUNT_FAILED, "device_busy"): "device busy",
        (VolumeState.MOUNT_FAILED, "os_partition"): "OS partition",
        (VolumeState.MOUNT_FAILED, "registry_entry_invalid"): "registry entry invalid",
    }
)

# Fragments shared by the steps, so no step text is written twice.
_MOUNT = "{cli} mount --volume {name}"
_SET_KEY = "{cli} set-key {name}"
_REPLUG = "replug the drive"
_CHKDSK = "chkdsk /f on it in Windows"
_JOURNAL = "journalctl -t steamos-mounter SM_VOLUME={name}"


def _sentence(text: str) -> str:
    return text[:1].upper() + text[1:]


# One table: (state, None) is the state's default; (state, reason) overrides it.
NEXT_STEP_TEXTS: Final[Mapping[tuple[VolumeState, str | None], str]] = MappingProxyType(
    {
        (VolumeState.NOT_PRESENT, None): "Plug the drive in.",
        (VolumeState.NOT_PRESENT, "record_unreadable"): (
            f"Plug the drive in; {_JOURNAL} shows what was unmounted."
        ),
        (VolumeState.NOT_MOUNTED, None): f"Run {_MOUNT}.",
        (VolumeState.NOT_MOUNTED, "record_unreadable"): (
            f"Run {_MOUNT}; {_JOURNAL} shows what was unmounted."
        ),
        (VolumeState.LOCKED, None): (
            "Unlock it in Dolphin; it mounts by itself after that."
        ),
        (VolumeState.NEEDS_KEY, None): (
            f"In Desktop Mode, {_REPLUG} or run {_MOUNT}. Or run {_SET_KEY}."
        ),
        (VolumeState.NEEDS_KEY, "dialog_open"): (
            "Answer the key dialog on the Deck's screen."
        ),
        (VolumeState.NEEDS_KEY, "dialog_failed"): (
            f"Run {_SET_KEY}, or unlock it in Dolphin."
        ),
        (VolumeState.NEEDS_KEY, "key_permissions"): (
            f"Run {{cli}} doctor, then {_SET_KEY}."
        ),
        (VolumeState.UNLOCK_FAILED, None): (
            f"{_sentence(_REPLUG)} or run {_MOUNT} to try again, or run {_SET_KEY}."
        ),
        (VolumeState.UNLOCK_CANCELLED, None): (
            f"{_sentence(_REPLUG)} or run {_MOUNT} when you want to unlock it."
        ),
        (VolumeState.MOUNTING, None): "Wait a few seconds and run list again.",
        (VolumeState.MOUNTED_RW, None): NO_NEXT_STEP,
        (VolumeState.MOUNTED_RW_DIRTY, None): f"Run {_CHKDSK}.",
        (VolumeState.MOUNTED_RO, None): f"See {_JOURNAL}.",
        (VolumeState.MOUNTED_RO, "unsafe"): (
            f"Shut Windows down fully (no Fast Startup), then run {_CHKDSK}."
        ),
        (VolumeState.MOUNTED_ELSEWHERE, None): (
            f"Unmount it there, then run {_MOUNT} to use the fixed path."
        ),
        (VolumeState.MOUNT_FAILED, None): f"See the journal, then run {_MOUNT}.",
        (VolumeState.MOUNT_FAILED, "fstype_mismatch"): (
            "Check that this is the right drive."
        ),
        (VolumeState.MOUNT_FAILED, "device_busy"): f"Wait, then run {_MOUNT}.",
        (VolumeState.MOUNT_FAILED, "no_free_name"): (
            f"Remove unused empty folders where drives are mounted, then {_REPLUG}."
        ),
        (VolumeState.MOUNT_FAILED, "registry_entry_invalid"): (
            "Run {cli} doctor to see what is wrong with the entry for {name}."
        ),
        (VolumeState.MOUNT_FAILED, "os_partition"): (
            "This is an OS partition; run {cli} remove {name}."
        ),
        (VolumeState.MOUNT_TIMED_OUT, None): f"Run {_MOUNT} to try again.",
        (VolumeState.UNMOUNTED_BY_USER, None): f"Run {_MOUNT}, or {_REPLUG}.",
    }
)

_WARNINGS: Final[Mapping[tuple[VolumeState, str], str]] = MappingProxyType(
    {
        (VolumeState.MOUNTED_RO, "unsafe"): (
            "{name} is in an " + UNSAFE_STATE + ". It is mounted read-only."
        ),
        (VolumeState.MOUNTED_RW_DIRTY, "dirty"): (
            "{name} is dirty: Windows did not close it cleanly. It is mounted"
            " read-write with ntfs-3g."
        ),
    }
)


def words(state: VolumeState, reason: str | None) -> str:
    """The plain words for ``state``, with a known reason's qualifier."""
    base = _WORDS[state]
    qualifier = _REASON_WORDS.get((state, reason)) if reason is not None else None
    return base if qualifier is None else f"{base}: {qualifier}"


def next_step(
    state: VolumeState, reason: str | None, *, name: str, cli_root: str
) -> str:
    """The next step for ``state`` and ``reason``; ``"-"`` when there is none.

    ``{cli}`` becomes ``cli_root`` and ``{name}`` the volume name; text in
    ``name`` is never read as a placeholder.
    """
    template = NEXT_STEP_TEXTS.get((state, reason), NEXT_STEP_TEXTS[(state, None)])
    return template.format(cli=cli_root, name=name)


def warning(state: VolumeState, reason: str | None, *, name: str) -> str | None:
    """The standard warning for a known cause (dirty, AC-017 unsafe), else None."""
    if reason is None:
        return None
    template = _WARNINGS.get((state, reason))
    return None if template is None else template.format(name=name)
