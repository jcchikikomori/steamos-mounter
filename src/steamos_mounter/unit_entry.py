"""The internal verbs the three template units run (``steamos-mounter internal …``).

Design Doc "CLI Contract > Internal Verbs" (DD-03, D011, D002), "Exit
Codes", the EARS block "Entry, Verbs and Guards" and IP-03; ADR-0001 (a
unit exits 0 after a decided outcome). ``cli.main`` hands every argv whose
first word is ``internal`` here, before the owner parser is built, so the
verbs never show in ``--help``::

    internal reconcile --trigger {start|reload} {registered|auto} PATH
    internal teardown {registered|auto} PATH
    internal sweep {registered|auto} PATH
    internal key PATH
    internal key-stop PATH

Order of a run:

1. Guards, in one function for every verb: platform (exit 4), ``euid == 0``
   (exit 3), ``INVOCATION_ID`` set (exit 2). Each writes one line on stderr
   and changes nothing.
2. The context: ``build_context`` sets up logging and creates the
   ``/run/steamos-mounter`` tree. When the tree fails closed the run logs
   ERROR and exits 0 without touching the device. An injected ``ctx``
   (tests) stands in for ``build_context``, so the tree step runs here.
3. The argv, parsed by hand (no argparse, which exits 2 on its own): a
   ``%f`` that breaks its kind's rule (AC-030 spirit) or a malformed argv is
   rejected, logged and exits 0.
4. The verb, from the verb table. ``sweep`` and ``key-stop`` read
   ``SERVICE_RESULT``, ``EXIT_CODE`` and ``EXIT_STATUS`` from the
   environment. Every exception is caught here: a ``LockTimeout`` (teardown
   waits ``LOCK_WAIT``; the sweep repeats the routine) is logged; anything
   else is logged at ERROR with the traceback, redacted by the logging
   setup, and recorded as ``MountFailed`` ``internal_error`` when the
   instance has a record. The exit status is 0.

Nothing here reaches the owner's ``mount`` path or starts a systemd job and
waits on it: each verb calls exactly one core entry.
"""

import dataclasses
import logging
import os
import re
from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import Final

from steamos_mounter import keyunit, locks, reconcile, records, teardown
from steamos_mounter.blockdev import KNAME_RE
from steamos_mounter.context import INVOCATION_ID_VARIABLE, Context, build_context
from steamos_mounter.errors import ExitCode, MounterError, UnsupportedPlatformError
from steamos_mounter.journal import fields
from steamos_mounter.model import InstanceKind, Trigger, VolumeState
from steamos_mounter.output import Output
from steamos_mounter.platforms import UNSUPPORTED_MESSAGE, current_platform
from steamos_mounter.reconcile_report import next_step
from steamos_mounter.records import Record
from steamos_mounter.teardown_report import Instance, ServiceResult, owner_for

INTERNAL: Final = "internal"
TRIGGER_OPTION: Final = "--trigger"
UNIT_TRIGGERS: Final = frozenset({Trigger.START.value, Trigger.RELOAD.value})
KINDS: Final = frozenset(kind.value for kind in InstanceKind)
# %f of a registered or key unit; an auto unit's %f is a sysfs path.
REGISTERED_PATH: Final = re.compile(r"/dev/disk/by-uuid/[0-9A-Fa-f-]{8,36}")
AUTO_PREFIX: Final = "/sys/devices/"
AUTO_BLOCK: Final = "/block/"

COMPONENT_HANDLER: Final = "handler"
COMPONENT_KEY_UNIT: Final = "key-unit"
REASON_INTERNAL: Final = reconcile.REASON_INTERNAL
ERROR_LOCK_WAIT: Final = reconcile.ERROR_LOCK_WAIT

NEEDS_ROOT: Final = "internal command: needs root."
NOT_FROM_SYSTEMD: Final = "internal command: started by systemd only."
BAD_ARGUMENTS: Final = "internal command: arguments not understood"
BAD_PATH: Final = "internal command: device path rejected"

log = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class Invocation:
    """One parsed verb: key units always address the registered record."""

    verb: str
    kind: InstanceKind
    path: str
    trigger: Trigger | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class Rejected:
    """An argv that is not a verb of this table, or a ``%f`` that breaks its rule."""

    message: str
    detail: str
    component: str = COMPONENT_HANDLER


@dataclasses.dataclass(frozen=True, slots=True)
class GuardFacts:
    """The inputs of the entry guards (DD-30, D011)."""

    on_platform: bool
    euid: int
    invocation_id: str | None


Parser = Callable[[str, Sequence[str]], "Invocation | Rejected"]
VerbBody = Callable[[Context, Invocation], object]


@dataclasses.dataclass(frozen=True, slots=True)
class Verb:
    component: str
    event: str  # SM_EVENT of the verb's journal entries
    parse: Parser
    run: VerbBody


def main(argv: Sequence[str], *, ctx: Context | None = None) -> int:
    """Run one internal verb; 4, 3 or 2 from the guards, else always 0."""
    parsed = _parse(argv)
    refused = _guard(guard_facts(ctx))
    if refused is not None:
        code, message = refused
        Output().error(message)
        return code
    component = parsed.component if isinstance(parsed, Rejected) else _component(parsed)
    try:
        ready = _context(ctx, component)
    except Exception as error:  # fail closed, exit 0 (ADR-0001)
        log.error(
            "internal command not run: %s %s",
            error,
            _detail(error),
            exc_info=not isinstance(error, MounterError),
            extra=fields(reason=REASON_INTERNAL),
        )
        return ExitCode.OK
    if isinstance(parsed, Rejected):
        log.warning("%s: %s", parsed.message, parsed.detail)
        return ExitCode.OK
    _dispatch(ready, parsed)
    return ExitCode.OK


# --- guards ---------------------------------------------------------------------------


def _guard(facts: GuardFacts) -> tuple[ExitCode, str] | None:
    """Platform, then root, then ``INVOCATION_ID`` (DD-30, D011); None: all pass."""
    if not facts.on_platform:
        return ExitCode.UNSUPPORTED_PLATFORM, f"{UNSUPPORTED_MESSAGE}."
    if facts.euid != 0:
        return ExitCode.NEEDS_ROOT, NEEDS_ROOT
    if not facts.invocation_id:
        return ExitCode.USAGE, NOT_FROM_SYSTEMD
    return None


def guard_facts(ctx: Context | None) -> GuardFacts:
    """What the guards read, before any write: from ``ctx``, or from the host.

    ``cli.main`` reads the same facts for its platform and root guards.
    """
    if ctx is not None:
        return GuardFacts(
            on_platform=ctx.platform.detect(ctx.paths),
            euid=ctx.euid,
            invocation_id=ctx.invocation_id,
        )
    try:
        current_platform()
    except UnsupportedPlatformError:
        on_platform = False
    else:
        on_platform = True
    return GuardFacts(
        on_platform=on_platform,
        euid=os.geteuid(),
        invocation_id=os.environ.get(INVOCATION_ID_VARIABLE) or None,
    )


def _context(ctx: Context | None, component: str) -> Context:
    if ctx is None:
        return build_context(component=component)
    records.ensure_runtime_dirs(ctx)
    return ctx


# --- parsing --------------------------------------------------------------------------


def _parse(argv: Sequence[str]) -> Invocation | Rejected:
    """The verb of ``argv`` (``internal`` first), or why it is rejected."""
    if len(argv) < 2 or argv[0] != INTERNAL or argv[1] not in VERBS:
        return Rejected(BAD_ARGUMENTS, f"argv {list(argv)!r}")
    verb = VERBS[argv[1]]
    parsed = verb.parse(argv[1], argv[2:])
    if isinstance(parsed, Rejected):
        return dataclasses.replace(parsed, component=verb.component)
    return parsed


def _parse_reconcile(name: str, args: Sequence[str]) -> Invocation | Rejected:
    if len(args) < 2 or args[0] != TRIGGER_OPTION or args[1] not in UNIT_TRIGGERS:
        return Rejected(BAD_ARGUMENTS, f"{name} {list(args)!r}")
    parsed = _parse_kind_path(name, args[2:])
    if isinstance(parsed, Rejected):
        return parsed
    return dataclasses.replace(parsed, trigger=Trigger(args[1]))


def _parse_kind_path(name: str, args: Sequence[str]) -> Invocation | Rejected:
    if len(args) != 2 or args[0] not in KINDS:
        return Rejected(BAD_ARGUMENTS, f"{name} {list(args)!r}")
    return _with_path(name, InstanceKind(args[0]), args[1])


def _parse_key(name: str, args: Sequence[str]) -> Invocation | Rejected:
    if len(args) != 1:
        return Rejected(BAD_ARGUMENTS, f"{name} {list(args)!r}")
    return _with_path(name, InstanceKind.REGISTERED, args[0])


def _with_path(name: str, kind: InstanceKind, path: str) -> Invocation | Rejected:
    if not _path_is_valid(kind, path):
        return Rejected(BAD_PATH, f"{name} {kind.value} {path!r}")
    return Invocation(verb=name, kind=kind, path=path)


def _path_is_valid(kind: InstanceKind, path: str) -> bool:
    """``%f`` of ``kind``: a by-uuid path, or a normalized sysfs block path.

    The auto path's last component is the kernel name, checked against
    ``KNAME_RE`` (AC-030) before anything reads sysfs with it.
    """
    if kind is InstanceKind.REGISTERED:
        return REGISTERED_PATH.fullmatch(path) is not None
    return (
        path.startswith(AUTO_PREFIX)
        and AUTO_BLOCK in path
        and os.path.normpath(path) == path
        and KNAME_RE.fullmatch(path.rpartition("/")[2]) is not None
    )


# --- dispatch and the top-level catch ------------------------------------------------


def _dispatch(ctx: Context, call: Invocation) -> None:
    """Run ``call``'s verb; every exception ends here (exit-0 discipline)."""
    verb = VERBS[call.verb]
    try:
        verb.run(ctx, call)
    except locks.LockTimeout as error:
        log.error(
            "internal %s of %s not done: %s %s",
            call.verb,
            call.path,
            error,
            error.detail,
            extra=fields(event=verb.event, reason="lock_timeout"),
        )
    except Exception as error:  # the one top-level catch (exit 0)
        log.error(
            "internal %s of %s failed: %s %s",
            call.verb,
            call.path,
            error,
            _detail(error),
            exc_info=error,
            extra=fields(event=verb.event, reason=REASON_INTERNAL),
        )
        _record_internal_error(ctx, call, verb.event)


def _record_internal_error(ctx: Context, call: Invocation, event: str) -> None:
    """``MountFailed`` ``internal_error`` in the instance's record, if it has one."""
    try:
        instance = teardown.locate(ctx, call.kind, call.path)
        if instance is None:
            return
        if not records.record_path(ctx, call.kind, instance.key).exists():
            return
        with locks.volume_lock(ctx, instance.lock_key, timeout=ERROR_LOCK_WAIT):
            records.update_record(
                ctx, call.kind, instance.key, _internal_error(ctx, instance)
            )
    except Exception as problem:  # noqa: BLE001 - still exit 0; the cause is logged
        log.error(
            "the internal error of %s could not be recorded: %s %s",
            call.path,
            problem,
            _detail(problem),
            extra=fields(event=event, reason=REASON_INTERNAL),
        )


def _internal_error(ctx: Context, instance: Instance) -> Callable[[Record], None]:
    def change(record: Record) -> None:
        source = record.source or {}
        owner = owner_for(instance, record.name, source.get("kname"))
        record.state = VolumeState.MOUNT_FAILED
        record.reason = REASON_INTERNAL
        record.warning = None
        record.next_step = next_step(
            ctx, owner, VolumeState.MOUNT_FAILED, REASON_INTERNAL
        )

    return change


def _detail(error: BaseException) -> str:
    return error.detail if isinstance(error, MounterError) else ""


def _component(call: Invocation) -> str:
    return VERBS[call.verb].component


# --- the verb table -------------------------------------------------------------------


def _reconcile(ctx: Context, call: Invocation) -> object:
    return reconcile.run(ctx, call.kind, call.path, Trigger(call.trigger))


def _teardown(ctx: Context, call: Invocation) -> object:
    return teardown.stop(ctx, call.kind, call.path)


def _sweep(ctx: Context, call: Invocation) -> object:
    svc = ServiceResult.from_environment(os.environ)
    return teardown.sweep(ctx, call.kind, call.path, svc)


def _key(ctx: Context, call: Invocation) -> object:
    return keyunit.run(ctx, call.path)


def _key_stop(ctx: Context, call: Invocation) -> object:
    svc = ServiceResult.from_environment(os.environ)
    return keyunit.stop_post(ctx, call.path, svc)


VERBS: Final[Mapping[str, Verb]] = MappingProxyType(
    {
        "reconcile": Verb(COMPONENT_HANDLER, "reconcile", _parse_reconcile, _reconcile),
        "teardown": Verb(COMPONENT_HANDLER, "teardown", _parse_kind_path, _teardown),
        "sweep": Verb(COMPONENT_HANDLER, "sweep", _parse_kind_path, _sweep),
        "key": Verb(COMPONENT_KEY_UNIT, "key", _parse_key, _key),
        "key-stop": Verb(COMPONENT_KEY_UNIT, "key", _parse_key, _key_stop),
    }
)
