"""Install step 10: start inactive instances of the devices plugged in now.

Design Doc "Python install" step 10 and ADR-0004 D7; split out of
``installer`` by step. Without this step a drive that was plugged in before
the install would wait for its next plug-in or the next boot.

- A registered volume whose ``/dev/disk/by-uuid`` link exists gets its
  registered instance started.
- An unregistered device that passes the udev rule's coarse filter (kernel
  name ``sd*``, ``mmcblk*`` or ``dm-*``, a filesystem type the rule lists)
  and that ``routing.route`` would not ignore gets its auto instance started,
  so the handler decides exactly what a plug-in would decide.

Only an ``inactive`` or ``failed`` instance is started, with ``--no-block``.
An active instance is never stopped, restarted or reloaded (ADR-0001).
"""

from typing import TYPE_CHECKING, Final

from steamos_mounter import blockdev, reconcile, routing, systemd
from steamos_mounter.blockdev import BlockDevice
from steamos_mounter.errors import ToolError
from steamos_mounter.escape import (
    BY_UUID_DIR,
    auto_instance,
    registered_instance,
    unit_name,
)
from steamos_mounter.installer_report import Done, Steps, ok, skipped
from steamos_mounter.model import InstanceKind, Registry
from steamos_mounter.routing import AUTO_TEMPLATE, REGISTERED_TEMPLATE, Action

if TYPE_CHECKING:
    from steamos_mounter.context import Context

# 90-steamos-mounter.rules: KERNEL and ENV{ID_FS_TYPE}.
RULE_KERNEL_PREFIXES: Final = ("sd", "mmcblk", "dm-")
RULE_FSTYPES: Final = frozenset({"ntfs", "exfat", "vfat", "btrfs", "BitLocker"})
# Routes whose instance would do nothing: no start. YIELD means registered.
NO_START_ACTIONS: Final = frozenset({Action.IGNORE, Action.REJECT, Action.YIELD})
STOPPED_STATES: Final = frozenset({"inactive", "failed"})
STATE_PROPERTIES: Final = ("LoadState", "ActiveState")
NOTHING: Final = "no present device to start"

Target = tuple[str, str]  # (label for the step line, unit)


def start_present(ctx: "Context", steps: Steps, registry: Registry) -> None:
    """One ``start <label>`` line per present device, or one ``start`` line."""
    targets = steps.attempt("start", lambda: _targets(ctx, registry))
    if targets is None:
        return
    for label, unit in targets:
        steps.run(f"start {label}", lambda unit=unit: _start(ctx, unit))


def _targets(ctx: "Context", registry: Registry) -> tuple[Done, tuple[Target, ...]]:
    found = (*_registered(ctx, registry), *_auto(ctx, registry))
    return (skipped(NOTHING) if not found else ok(f"{len(found)} present")), found


def _registered(ctx: "Context", registry: Registry) -> list[Target]:
    return [
        (volume.name, unit_name(REGISTERED_TEMPLATE, registered_instance(volume.uuid)))
        for volume in sorted(registry.volumes, key=lambda volume: volume.name)
        if ctx.paths.p(BY_UUID_DIR + volume.uuid).exists()
    ]


def _auto(ctx: "Context", registry: Registry) -> list[Target]:
    tree = blockdev.read_tree(ctx)
    blocked = registry.blocked_uuids()
    found: list[Target] = []
    for kname in sorted(tree.devices):
        device = tree.devices[kname]
        if not _rule_matches(device) or (device.uuid or "").lower() in blocked:
            continue
        route = routing.route(reconcile.gather(ctx, InstanceKind.AUTO, kname))
        syspath = blockdev.syspath(ctx, kname)
        if route.action in NO_START_ACTIONS or syspath is None:
            continue
        found.append(
            (f"/dev/{kname}", unit_name(AUTO_TEMPLATE, auto_instance(syspath)))
        )
    return found


def _rule_matches(device: BlockDevice) -> bool:
    return device.kname.startswith(RULE_KERNEL_PREFIXES) and (
        device.fstype in RULE_FSTYPES
    )


def _start(ctx: "Context", unit: str) -> Done:
    properties = systemd.show(ctx, unit, STATE_PROPERTIES)
    state = properties.get("ActiveState", "") if systemd.unit_exists(properties) else ""
    if state and state not in STOPPED_STATES:
        return skipped(state)
    result = systemd.start(ctx, unit, block=False)
    if result.returncode != 0:
        raise ToolError(
            "the instance did not start: run install.sh again",
            detail=(
                f"systemctl start {unit}: exit {result.returncode}, timed out "
                f"{result.timed_out}: {result.err_text().strip()}"
            ),
        )
    return ok()
