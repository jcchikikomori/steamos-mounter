"""The systemctl wrapper: the ``show`` parser, unit verbs, delegated reloads.

Design Doc "Module Responsibilities > systemd", DD-12 (D006) and the Fact
Disposition Table row "systemd-escape:instance-naming". Two parser traps from
the Deck captures:

- ``systemctl show`` prints most values raw (``Id=dev-dm\\x2d0.device``) but
  quotes some, doubling their backslashes (``Names="dev-dm\\\\x2d0.device"``);
  ``parse_show`` strips the quotes and halves the backslashes, so both name
  the same unit;
- a unit that does not exist reports ``Result=success`` and
  ``ActiveState=inactive``; only ``LoadState=not-found`` says it is missing,
  so ``LoadState`` is read before anything else (``unit_exists``).

``request_reconcile`` is the one way a component asks another instance to
reconcile (a ``dm-*`` instance or the key unit asking the partition
instance). It reloads with ``--no-block`` and never starts a unit: an
instance the owner or systemd stopped stays stopped.
"""

import logging
import re
import time
from collections.abc import Sequence
from typing import TYPE_CHECKING, Final, Literal

from steamos_mounter.errors import ToolError
from steamos_mounter.journal import fields
from steamos_mounter.runner import Command, CommandResult

if TYPE_CHECKING:
    from steamos_mounter.context import Context

VERB_TIMEOUT: Final = 120.0
QUERY_TIMEOUT: Final = 10.0
WAIT_ACTIVATING: Final = 15.0
POLL_SECONDS: Final = 0.5
NOT_FOUND: Final = "not-found"
# A start or stop job is running (DD-12): a reload may merge into it.
BUSY_STATES: Final = frozenset({"activating", "deactivating"})
GONE_STATES: Final = frozenset({"inactive", "failed"})
STATE_PROPERTIES: Final = ("LoadState", "ActiveState")
NO_INSTANCE: Final = "no partition instance"

# A unit name or a glob over unit names: no whitespace, no control characters,
# no leading "-" (argv stays unambiguous even before the "--").
_UNIT_NAME: Final = re.compile(r"[^\s\x00-\x1f\x7f-][^\s\x00-\x1f\x7f]*")
_PROPERTY_NAME: Final = re.compile(r"[A-Za-z][A-Za-z0-9]*")
_QUOTE: Final = '"'
# One pass, so a doubled backslash before a quote is never read as an escaped quote.
_QUOTED_ESCAPE: Final = re.compile(r'\\([\\"])')
_NO_BLOCK: Final = "--no-block"
_END_OF_OPTIONS: Final = "--"
_CALL_FAILED: Final = "a systemd request failed"

log = logging.getLogger(__name__)

Outcome = Literal["absent", "reloaded", "reloaded-after-wait"]


def parse_show(text: str) -> dict[str, str]:
    """``Property=value`` lines as a dict; quoted values are unquoted.

    A value that starts and ends with ``"`` loses the quotes, and its ``\\\\``
    and ``\\"`` become ``\\`` and ``"``. Raw values are kept as they are.
    Lines without ``=`` (blank lines, separators) are skipped.
    """
    properties: dict[str, str] = {}
    for line in text.splitlines():
        name, found, value = line.partition("=")
        if found and name:
            properties[name] = _unquote(value)
    return properties


def _unquote(value: str) -> str:
    if len(value) < 2 or not (value.startswith(_QUOTE) and value.endswith(_QUOTE)):
        return value
    return _QUOTED_ESCAPE.sub(r"\1", value[1:-1])


def unit_exists(properties: dict[str, str]) -> bool:
    """False for ``LoadState=not-found`` or no ``LoadState`` at all.

    Read before ``Result=``: a missing unit says ``Result=success``.
    """
    load_state = properties.get("LoadState")
    return load_state is not None and load_state != NOT_FOUND


def show(ctx: "Context", unit: str, props: Sequence[str]) -> dict[str, str]:
    """``systemctl show --property=<props> -- <unit>``, parsed.

    A missing unit is not an error (``LoadState=not-found``). A failed or
    timed-out call raises ``ToolError``.
    """
    _check_unit(unit)
    if not props or any(_PROPERTY_NAME.fullmatch(name) is None for name in props):
        raise ValueError(f"not a list of systemd property names: {list(props)!r}")
    argv = (
        ctx.platform.tools.systemctl,
        "show",
        f"--property={','.join(props)}",
        _END_OF_OPTIONS,
        unit,
    )
    result = ctx.runner.run(Command(argv=argv, timeout=QUERY_TIMEOUT))
    _require_success(result, "show")
    return parse_show(result.text())


def start(
    ctx: "Context", unit: str, *, block: bool, timeout: float = VERB_TIMEOUT
) -> CommandResult:
    """``systemctl start``; the caller reads the result."""
    return _verb(ctx, "start", (unit,), block=block, timeout=timeout)


def reload(
    ctx: "Context", unit: str, *, block: bool, timeout: float = VERB_TIMEOUT
) -> CommandResult:
    """``systemctl reload``; the caller reads the result."""
    return _verb(ctx, "reload", (unit,), block=block, timeout=timeout)


def stop(
    ctx: "Context", units: Sequence[str], *, block: bool, timeout: float = VERB_TIMEOUT
) -> CommandResult:
    """``systemctl stop`` of one or more units; the caller reads the result."""
    if not units:
        raise ValueError("stop needs at least one unit")
    return _verb(ctx, "stop", tuple(units), block=block, timeout=timeout)


def request_reconcile(
    ctx: "Context", unit: str, *, wait_activating: float = WAIT_ACTIVATING
) -> Outcome:
    """Ask ``unit`` to reconcile again, without a job dependency (DD-12).

    - ``active``: one ``reload --no-block`` -> ``"reloaded"``.
    - ``activating`` or ``deactivating`` (a job is running, and a reload may
      be merged into it): reload now, poll ``ActiveState`` on ``ctx.clock``
      for at most ``wait_activating`` seconds until it leaves that state,
      then reload again -> ``"reloaded-after-wait"``. If the instance is gone
      by then, nothing more is sent -> ``"absent"``.
    - ``inactive``, ``failed`` or a missing unit: nothing is sent, never a
      start; one WARNING "no partition instance" -> ``"absent"``.

    A failed reload is logged at WARNING and does not change the outcome:
    the request was made. A failed ``show`` raises ``ToolError``.
    """
    active = _active_state(ctx, unit)
    if active is None or active in GONE_STATES:
        return _absent(unit, active)
    _request_reload(ctx, unit)
    if active not in BUSY_STATES:
        return "reloaded"
    active = _wait_while_busy(ctx, unit, active, wait_activating)
    if active is None or active in GONE_STATES:
        return _absent(unit, active)
    _request_reload(ctx, unit)
    return "reloaded-after-wait"


def daemon_reload(ctx: "Context") -> None:
    """``systemctl daemon-reload``; a failure raises ``ToolError``."""
    argv = (ctx.platform.tools.systemctl, "daemon-reload")
    result = ctx.runner.run(Command(argv=argv, timeout=VERB_TIMEOUT))
    _require_success(result, "daemon-reload")


def list_units(ctx: "Context", patterns: Sequence[str]) -> tuple[str, ...]:
    """Names of loaded units matching ``patterns``, in systemctl's order.

    Includes inactive and failed ones (``--all``). A failed call raises
    ``ToolError``.
    """
    if not patterns:
        raise ValueError("list_units needs at least one pattern")
    for pattern in patterns:
        _check_unit(pattern)
    argv = (
        ctx.platform.tools.systemctl,
        "list-units",
        "--all",
        "--plain",
        "--no-legend",
        "--no-pager",
        "--full",
        _END_OF_OPTIONS,
        *patterns,
    )
    result = ctx.runner.run(Command(argv=argv, timeout=QUERY_TIMEOUT))
    _require_success(result, "list-units")
    return tuple(line.split()[0] for line in result.text().splitlines() if line.strip())


def _verb(
    ctx: "Context",
    verb: str,
    units: tuple[str, ...],
    *,
    block: bool,
    timeout: float,
) -> CommandResult:
    for unit in units:
        _check_unit(unit)
    options = () if block else (_NO_BLOCK,)
    argv = (ctx.platform.tools.systemctl, verb, *options, _END_OF_OPTIONS, *units)
    return ctx.runner.run(Command(argv=argv, timeout=timeout))


def _check_unit(unit: str) -> None:
    if _UNIT_NAME.fullmatch(unit) is None:
        raise ValueError(f"not a unit name: {unit!r}")


def _require_success(result: CommandResult, verb: str) -> None:
    if result.returncode == 0:
        return
    raise ToolError(
        _CALL_FAILED,
        detail=(
            f"systemctl {verb}: exit {result.returncode}, timed out "
            f"{result.timed_out}, not found {result.not_found}: "
            f"{result.err_text().strip()}"
        ),
    )


def _active_state(ctx: "Context", unit: str) -> str | None:
    """``ActiveState`` of ``unit``; None when the unit does not exist."""
    properties = show(ctx, unit, STATE_PROPERTIES)
    if not unit_exists(properties):
        return None
    return properties.get("ActiveState", "")


def _wait_while_busy(
    ctx: "Context", unit: str, active: str | None, limit: float
) -> str | None:
    """Poll until ``unit`` leaves a busy state or ``limit`` seconds pass."""
    deadline = ctx.clock.monotonic() + max(limit, 0.0)
    while active in BUSY_STATES and ctx.clock.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
        active = _active_state(ctx, unit)
    return active


def _request_reload(ctx: "Context", unit: str) -> None:
    result = reload(ctx, unit, block=False)
    if result.returncode != 0:
        log.warning(
            "reload request for %s failed: exit %s, %s",
            unit,
            result.returncode,
            result.err_text().strip(),
            extra=fields(unit=unit, event="delegate"),
        )


def _absent(unit: str, active: str | None) -> Outcome:
    log.warning(
        "%s: %s is %s; it is not started",
        NO_INSTANCE,
        unit,
        active or NOT_FOUND,
        extra=fields(unit=unit, event="delegate"),
    )
    return "absent"
