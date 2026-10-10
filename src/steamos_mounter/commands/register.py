"""``add`` and ``remove``: register a volume, and take it out again.

Design Doc "CLI Contract > Commands" (``add`` steps 1 to 7, ``remove``),
"Key Store", "Fixed-path Rules" (DD-31 rule 8, DD-34 rule 9) and DD-28;
ADR-0002 D6 (the wiring follows the registry), ADR-0004 D4 (key input, test
before storage) and D8 (unwire first, then stop).

``add``, in order: the registry (unusable: exit 1); the device by
``--device`` (``realpath``) or ``--uuid`` (exact), a shared UUID refused;
the ``commands.eligibility`` refusals (exit 8); a registry with an invalid
entry (exit 1: a rewrite would drop it, so the owner fixes it by hand
first); ``ensure_mount_base``, so a base that ``/run`` lost at a reboot
never trips rule 7 (exit 1 when it cannot be made, config unchanged); the
name, the path (a direct child of the mount base) and the drivers, each
validated; for BitLocker the key, read from a hidden prompt, ``--key-file``
or ``--key-stdin`` (never argv), tested with cryptsetup, then stored; the
registry write and the wiring under one hold of the registry lock, then
``daemon-reload``; last, a start of the inactive registered instance. Every
refusal happens before the key is asked for, and nothing is written before
the last check passed.

``remove NAME``: a registry with an invalid entry stops it first (exit 1),
even when NAME is that entry's; then unwire (the volume's link,
``daemon-reload``), stop the key unit when it runs, stop the registered
instance blocking (its teardown unmounts and closes), then remove the entry,
the key and the record. Items the teardown left busy print one line each
and give exit 6.
"""

import argparse
import getpass
import io
import logging
import posixpath
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from steamos_mounter import (
    bitlocker,
    config,
    keystore,
    locks,
    mountdirs,
    mounts,
    records,
    systemd,
    wiring,
)
from steamos_mounter.bitlocker import UnlockOutcome
from steamos_mounter.commands import Command, Invocation, devices, eligibility
from steamos_mounter.errors import ExitCode, RefusedError, ToolError, UsageError
from steamos_mounter.escape import BY_UUID_DIR
from steamos_mounter.journal import NOTICE, fields
from steamos_mounter.model import InstanceKind, MountInfo, Registry, Step, Volume
from steamos_mounter.naming import (
    REGISTRY_NAME_RE,
    fallback_name,
    propose_registry_name,
    validate_fixed_path,
)
from steamos_mounter.ntfs import parse_drivers
from steamos_mounter.reconcile_report import Owner
from steamos_mounter.reconcile_unlock import key_unit_name
from steamos_mounter.records import Record
from steamos_mounter.routing import BITLOCKER
from steamos_mounter.sensitive import SecretBytes

if TYPE_CHECKING:
    from steamos_mounter.blockdev import BlockDevice
    from steamos_mounter.context import Context

ADD: Final = "add"
REMOVE: Final = "remove"
DRIVERS_FSTYPES: Final = config.DRIVERS_FSTYPES
STOPPED_STATES: Final = frozenset({"inactive", "failed"})
KEY_REJECTED: Final = "the key was not accepted. Nothing was stored"
KEY_CHECK_FAILED: Final = "the key could not be checked: cryptsetup failed"
BAD_NAME: Final = (
    "{name} is not a valid name: use up to 64 letters, digits, '.', '_' or '-',"
    " starting with a letter or digit"
)
DRIVERS_ONLY: Final = "--drivers is only for ntfs and BitLocker volumes"
FIXED_PATH_LATER: Final = (
    "{name} is mounted at {at} now. The fixed path applies from the next"
    " plug-in, boot, or mount after an unmount"
)

log = logging.getLogger(__name__)


# --- arguments ------------------------------------------------------------------------


def configure_add(parser: argparse.ArgumentParser) -> None:
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--device", metavar="DEV", help="the device, e.g. /dev/sdb5")
    which.add_argument("--uuid", metavar="UUID", help="the filesystem UUID, exactly")
    parser.add_argument("--name", metavar="NAME", help="registry name (default: label)")
    parser.add_argument(
        "--path", metavar="PATH", help="mount path (default: <mount base>/<name>)"
    )
    parser.add_argument(
        "--drivers",
        metavar="LIST",
        help="comma-separated NTFS steps, e.g. ntfs3,ntfs-3g,ntfs3:ro",
    )
    parser.add_argument("--allow-suid", action="store_true", help="drop nosuid")
    parser.add_argument("--allow-devices", action="store_true", help="drop nodev")
    add_key_options(parser)


def add_key_options(parser: argparse.ArgumentParser) -> None:
    """``--key-file FILE`` or ``--key-stdin``; neither: the hidden prompt (AC-012)."""
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--key-file", metavar="FILE", help="read the BitLocker key from FILE"
    )
    source.add_argument(
        "--key-stdin", action="store_true", help="read the BitLocker key from stdin"
    )


def configure_remove(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("name", metavar="NAME", help="the registered volume")


# --- add ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Add:
    """What ``add`` read once: the registry, the device and the mount table."""

    ctx: "Context"
    args: argparse.Namespace
    registry: Registry
    device: "BlockDevice"
    stacked: tuple["BlockDevice", ...]
    table: tuple[MountInfo, ...]


def run_add(call: Invocation) -> ExitCode:
    ctx, args = call.ctx, call.args
    registry = devices.load_registry(ctx)
    facts = eligibility.gather(ctx, registry)
    if args.device is not None:
        device = devices.find_device(ctx, facts.tree, args.device)
    else:
        device = devices.find_uuid(facts.tree, args.uuid)
    devices.require_unique(facts.tree, device)
    reason = eligibility.why_not_registrable(device, facts)
    if reason is not None:
        raise _refused(device, reason)
    config.require_rewritable(registry)
    mountdirs.ensure_mount_base(ctx)
    plan = _Add(
        ctx,
        args,
        registry,
        device,
        devices.stacked_on(facts.tree, device),
        mounts.table(ctx),
    )
    volume = _volume(plan)
    if volume.fstype == BITLOCKER:
        _store_tested_key(plan, volume)
    _save(ctx, volume)
    log.log(
        NOTICE,
        "registered %s (%s) at %s",
        volume.name,
        volume.uuid,
        volume.path,
        extra=fields(volume=volume.name, uuid=volume.uuid, event=ADD),
    )
    _announce(call, plan, volume)
    return ExitCode.OK


def _refused(device: "BlockDevice", reason: str) -> RefusedError:
    return RefusedError(
        f"cannot register /dev/{device.kname}: {reason}",
        detail=f"add refused /dev/{device.kname}: {reason}",
    )


def _volume(plan: _Add) -> Volume:
    """The entry to add, checked against every rule a read and a mount apply."""
    device, args = plan.device, plan.args
    base = plan.ctx.platform.mount_base
    name = args.name or propose_registry_name(
        device.label, fallback=fallback_name(device.fstype, device.uuid, device.kname)
    )
    if REGISTRY_NAME_RE.fullmatch(name) is None:
        raise UsageError(BAD_NAME.format(name=name))
    path = args.path or posixpath.join(base, name)
    facts = mountdirs.HostPathFacts(
        plan.ctx.paths, trusted_uid=plan.ctx.platform.trusted_uid
    )
    try:
        validate_fixed_path(
            path, mount_base=base, other_paths=_taken_paths(plan), fs=facts
        )
    except RefusedError as refused:
        raise _refused(device, refused.user_message) from refused
    volume = Volume(
        name=name,
        uuid=device.uuid or "",
        path=path,
        fstype=device.fstype or "",
        drivers=_drivers(args.drivers, device.fstype),
        nosuid=not args.allow_suid,
        nodev=not args.allow_devices,
    )
    try:
        config.with_volume(plan.registry, volume, mount_base=base)
    except RefusedError as refused:
        raise _refused(device, refused.user_message) from refused
    return volume


def _taken_paths(plan: _Add) -> list[str]:
    """Registered paths and every live mount below the mount base (rule 6)."""
    base = plan.ctx.platform.mount_base.rstrip("/") + "/"
    taken = [volume.path for volume in plan.registry.volumes]
    taken += [row.target for row in plan.table if row.target.startswith(base)]
    return taken


def _drivers(text: str | None, fstype: str | None) -> tuple[Step, ...] | None:
    if text is None:
        return None
    if fstype not in DRIVERS_FSTYPES:
        raise UsageError(DRIVERS_ONLY)
    try:
        return parse_drivers([token.strip() for token in text.split(",")])
    except ValueError as error:
        reason = str(error).removeprefix("drivers: ")
        raise UsageError(f"--drivers: {reason}") from error


def read_key(args: argparse.Namespace, *, prompt_text: str) -> SecretBytes:
    """The key from ``--key-file``, ``--key-stdin`` or the hidden prompt.

    ``set-key`` reads its key the same way.
    """
    if args.key_file is not None:
        source = "file"
    elif args.key_stdin:
        source = "stdin"
    else:
        source = "prompt"
    stdin = sys.stdin.buffer if source == "stdin" else io.BytesIO()
    return keystore.read_key_input(
        source=source,
        prompt_text=prompt_text,
        file_path=args.key_file,
        stdin=stdin,
        tty_prompt=getpass.getpass,
    )


def verify_and_store(ctx: "Context", device: str, uuid: str, key: SecretBytes) -> None:
    """``test_key``, then ``keystore.store``: a rejected key is exit 8 (AC-050).

    A cryptsetup failure other than a rejection is a ``ToolError`` (IP-10).
    """
    outcome = bitlocker.test_key(ctx, device, key)
    if outcome is UnlockOutcome.REJECTED:
        raise RefusedError(KEY_REJECTED, detail=f"{device}: key rejected")
    if outcome is not UnlockOutcome.OPENED:
        raise ToolError(KEY_CHECK_FAILED, detail=f"{device}: test_key {outcome}")
    keystore.store(ctx, uuid, key)


def _store_tested_key(plan: _Add, volume: Volume) -> None:
    with read_key(plan.args, prompt_text=f"BitLocker key for {volume.name}: ") as key:
        verify_and_store(plan.ctx, f"/dev/{plan.device.kname}", volume.uuid, key)


def _save(ctx: "Context", volume: Volume) -> None:
    """Write the entry and the wiring under one registry lock, then reload."""
    base = ctx.platform.mount_base

    def change(current: Registry) -> Registry:
        return config.with_volume(current, volume, mount_base=base)

    config.update(ctx, change, then=lambda saved: wiring.sync_links(ctx, saved))
    systemd.daemon_reload(ctx)


def _announce(call: Invocation, plan: _Add, volume: Volume) -> None:
    """The registered name and path, then what happens next (step 7)."""
    ctx, out = call.ctx, call.out
    out.line(f"registered {volume.name} ({volume.uuid}) at {volume.path}")
    elsewhere = [row.target for row in _mounts_of(plan) if row.target != volume.path]
    owner = devices.registered_owner(volume, plan.device)
    if devices.active_state(ctx, owner.unit) in STOPPED_STATES:
        _start(call, owner.unit, volume)
    if elsewhere:
        out.line(FIXED_PATH_LATER.format(name=volume.name, at=elsewhere[0]))


def _mounts_of(plan: _Add) -> list[MountInfo]:
    rows: list[MountInfo] = []
    for device in (plan.device, *plan.stacked):
        rows.extend(mounts.for_device(plan.table, device, None))
    return rows


def _start(call: Invocation, unit: str, volume: Volume) -> None:
    result = systemd.start(call.ctx, unit, block=False)
    if result.returncode == 0:
        call.out.line(f"mounting {volume.name} at {volume.path} now")
        return
    log.warning(
        "%s: %s did not start: exit %s, %s",
        volume.name,
        unit,
        result.returncode,
        result.err_text().strip(),
        extra=fields(volume=volume.name, unit=unit, event=ADD),
    )
    call.out.line(
        f"{volume.name} could not be mounted now. Run "
        f"{call.ctx.platform.cli_root} mount --volume {volume.name}"
    )


# --- remove ---------------------------------------------------------------------------


def run_remove(call: Invocation) -> ExitCode:
    ctx, out = call.ctx, call.out
    registry = devices.load_registry(ctx)
    config.require_rewritable(registry)
    volume = devices.registered(registry, call.args.name)
    owner = devices.registered_owner(volume, None)
    _unwire(ctx, volume)
    out.line(f"unwired {volume.name}")
    _stop(ctx, owner)
    out.line(f"stopped {volume.name}")
    busy = _busy(ctx, owner)
    _forget(ctx, volume)
    key_deleted = keystore.delete(ctx, volume.uuid)
    with locks.volume_lock(ctx, owner.lock_key, timeout=devices.CLI_LOCK_WAIT):
        records.delete_record(ctx, InstanceKind.REGISTERED, owner.key)
    log.log(
        NOTICE,
        "removed %s",
        volume.name,
        extra=fields(volume=volume.name, uuid=volume.uuid, event=REMOVE),
    )
    out.line(f"removed {volume.name}" + (" and its key" if key_deleted else ""))
    for item in busy:
        out.line(f"busy: {item} is released once nothing uses it any more")
    return ExitCode.BUSY if busy else ExitCode.OK


def _unwire(ctx: "Context", volume: Volume) -> None:
    """Remove the volume's link first, so no plug-in starts it again (D8)."""
    with locks.registry_lock(ctx):
        current = config.load(ctx)
        wiring.sync_links(ctx, config.without_volume(current, volume.name))
    systemd.daemon_reload(ctx)


def _stop(ctx: "Context", owner: Owner) -> None:
    """The key unit when it runs (closes its dialog), then the instance, blocking."""
    key_unit = key_unit_name(BY_UUID_DIR + owner.uuid)
    if devices.active_state(ctx, key_unit) in devices.RUNNING_STATES:
        _stop_unit(ctx, key_unit, owner)
    _stop_unit(ctx, owner.unit, owner)


def _stop_unit(ctx: "Context", unit: str, owner: Owner) -> None:
    result = systemd.stop(ctx, (unit,), block=True)
    if result.returncode != 0:
        raise ToolError(
            f"{owner.name} could not be stopped. Run remove again",
            detail=(
                f"systemctl stop {unit}: exit {result.returncode}, timed out "
                f"{result.timed_out}: {result.err_text().strip()}"
            ),
        )


def _busy(ctx: "Context", owner: Owner) -> Sequence[str]:
    """What the teardown could only lazily unmount or deferred-close."""
    found = records.load_record(ctx, InstanceKind.REGISTERED, owner.key)
    return tuple(found.busy) if isinstance(found, Record) else ()


def _forget(ctx: "Context", volume: Volume) -> None:
    """Remove the entry and re-derive the wiring under one registry lock."""
    changes: list[wiring.WiringChange] = []

    def change(current: Registry) -> Registry:
        return config.without_volume(current, volume.name)

    config.update(
        ctx, change, then=lambda saved: changes.append(wiring.sync_links(ctx, saved))
    )
    if any(change.created or change.removed for change in changes):
        systemd.daemon_reload(ctx)


COMMANDS: Final = (
    Command(
        name=ADD,
        summary="register a volume: mount it at a fixed path at every plug-in",
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
        configure=configure_add,
        run=run_add,
    ),
    Command(
        name=REMOVE,
        summary="unregister a volume: unwire, stop, and remove its entry and key",
        root_only=True,
        exit_codes=frozenset(
            {
                ExitCode.OK,
                ExitCode.FAILED,
                ExitCode.USAGE,
                ExitCode.NEEDS_ROOT,
                ExitCode.UNSUPPORTED_PLATFORM,
                ExitCode.BUSY,
            }
        ),
        configure=configure_remove,
        run=run_remove,
    ),
)
