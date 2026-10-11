"""``add`` takes over the mount its own auto instance made of the device.

Owner decision 2026-10-11 (Stage B, B1.3): plugging in a drive auto-mounts it
at ``<mount base>/<label>``, which is also the fixed path ``add`` proposes,
so the natural first ``add`` used to trip rules 5 and 6 on the tool's own
mount.

- **Evidence**: the auto record of the device names a mount of its own
  (``pending`` or ``mounted``), and the live mount table has a row of the
  device or the inner device stacked on it with that record's target and
  device number. The path alone never counts; a udisks, Dolphin or manual
  mount has no such record and is refused as before.
- **Path rules**: rule 5 sees that target as the leaf it was before the
  mount, and rule 6 leaves that one row out. Every other mount and every
  other non-empty directory still refuses.
- **Release**: after the registry, the wiring and ``daemon-reload``, the
  mount goes through ``unmount``'s own code (``mounting.release``), so the
  auto record ends ``UnmountedByUser`` as it does there. When it stays (busy,
  or a failed unmount), ``add`` keeps the registration and does not start the
  registered instance.
"""

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from steamos_mounter import records
from steamos_mounter.commands import Invocation, devices, mounting
from steamos_mounter.errors import MounterError
from steamos_mounter.journal import fields
from steamos_mounter.model import InstanceKind, MountInfo
from steamos_mounter.naming import PathFacts, PathKind
from steamos_mounter.reconcile_report import Owner, record_key
from steamos_mounter.records import Record

if TYPE_CHECKING:
    from collections.abc import Sequence

    from steamos_mounter.blockdev import BlockDevice
    from steamos_mounter.context import Context

TAKEOVER: Final = "add"

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AutoMount:
    """The auto instance's own mount of the device being registered."""

    owner: Owner
    target: str
    devnum: str

    def is_row(self, row: MountInfo) -> bool:
        return row.target == self.target and row.devnum == self.devnum


def find(
    ctx: "Context", device: "BlockDevice", rows: "Sequence[MountInfo]"
) -> AutoMount | None:
    """The auto mount of ``device`` both its record and ``rows`` show, else None.

    ``rows`` are the live rows of ``device`` and the devices stacked on it.
    """
    found = records.load_record(ctx, InstanceKind.AUTO, record_key(device))
    if not isinstance(found, Record):
        return None
    target = records.own_mount_target(found)
    devnum = (found.mount or {}).get("devnum")
    if target is None or not isinstance(devnum, str):
        return None
    mount = AutoMount(devices.auto_owner(ctx, device), target, devnum)
    return mount if any(mount.is_row(row) for row in rows) else None


class BeforeTheMount:
    """``PathFacts`` that see ``target`` as the leaf under the mount (rule 5).

    The auto instance mounted only on a missing or empty leaf, and the
    registered instance checks the leaf again before its own mount.
    """

    def __init__(self, facts: PathFacts, target: str) -> None:
        self._facts = facts
        self._target = target

    def kind(self, path: str) -> PathKind:
        if path == self._target:
            return PathKind.EMPTY_DIR
        return self._facts.kind(path)

    def trusted_dir(self, path: str) -> bool:
        return self._facts.trusted_dir(path)


def release(call: Invocation, mount: AutoMount, *, volume: str) -> bool:
    """Unmount ``mount`` as ``unmount`` does; False when it stays mounted.

    ``volume`` is the name just registered: the output line and the journal
    use it.
    """
    owner = mount.owner
    extra = fields(volume=volume, uuid=owner.uuid or None, event=TAKEOVER)
    try:
        done = mounting.release(call.ctx, owner)
    except MounterError as error:
        log.warning(
            "%s: the auto mount at %s stays: %s",
            volume,
            mount.target,
            error.detail or error.user_message,
            extra=extra,
        )
        return False
    if done.target is not None:
        call.out.line(f"unmounted {volume} from {done.target}")
    if done.close_failed is not None:
        log.warning(
            "%s: unmounted from %s, but %s stays open",
            volume,
            mount.target,
            done.close_failed,
            extra=extra,
        )
    return True
