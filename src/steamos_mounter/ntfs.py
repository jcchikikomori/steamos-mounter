"""The NTFS chain: ``drivers`` spelling, the unsafe-volume probe and planning.

Design Doc "NTFS Chain, Mount Options and Read-back" ("drivers Spelling",
"Guard and Planning") and ADR-0003 Decisions 1 and 3. ``mounter`` runs the
planned steps; this module only decides which ones may run.

- ``drivers`` tokens map one-to-one to chain steps; a list replaces the
  default chain and keeps its order (AC-019). The kernel ``ntfs`` driver runs
  only when listed (NFR-13).
- ``ntfs-3g.probe --readwrite`` exits 0 safe, 15 dirty (unclean ``$LogFile``),
  14 hibernated and 16 held. A volume carrying only the dirty flag exits 0;
  the kernel ``ntfs3`` driver refuses it and says so in the kernel log.
  Every other outcome, 13 (inconsistent, such as a ``$MFTMirr`` mismatch)
  included, is unsafe: fail closed.
- Unsafe removes only the kernel read-write steps. ``ntfs-3g`` rw still runs
  and refuses or falls back to read-only by itself, then the read-only steps
  follow (owner rule I006). Held runs nothing (AC-034).
"""

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from steamos_mounter.model import Driver, Mode, Step
from steamos_mounter.runner import Command

if TYPE_CHECKING:
    from steamos_mounter.context import Context

READ_ONLY_SUFFIX: Final = ":ro"
NTFS_DRIVERS: Final = (Driver.NTFS3, Driver.NTFS3G, Driver.NTFS)


def _token(step: Step) -> str:
    return f"{step.driver}{READ_ONLY_SUFFIX if step.mode is Mode.RO else ''}"


# The Design Doc's "drivers Spelling" table: six tokens, each one chain step.
DRIVER_STEPS: Final[Mapping[str, Step]] = MappingProxyType(
    {
        _token(step): step
        for step in (Step(driver, mode) for driver in NTFS_DRIVERS for mode in Mode)
    }
)
DRIVER_TOKENS: Final = frozenset(DRIVER_STEPS)
DEFAULT_CHAIN: Final = (
    Step(Driver.NTFS3, Mode.RW),
    Step(Driver.NTFS3G, Mode.RW),
    Step(Driver.NTFS3, Mode.RO),
)
# The steps an unsafe probe result removes: kernel drivers writing.
KERNEL_RW_STEPS: Final = frozenset(
    {Step(Driver.NTFS3, Mode.RW), Step(Driver.NTFS, Mode.RW)}
)

PROBE_NAME: Final = "ntfs-3g.probe"
PROBE_TIMEOUT: Final = 20.0

log = logging.getLogger(__name__)


class ProbeClass(StrEnum):
    SAFE = "safe"
    DIRTY = "dirty"
    UNSAFE = "unsafe"
    HELD = "held"


# ADR-0003 Decision 3. A code not listed here is unsafe (fail closed).
PROBE_CLASSES: Final[Mapping[int, ProbeClass]] = MappingProxyType(
    {
        0: ProbeClass.SAFE,
        15: ProbeClass.DIRTY,
        14: ProbeClass.UNSAFE,
        16: ProbeClass.HELD,
    }
)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """One probe run. ``code`` is None when it timed out or was not found."""

    code: int | None
    klass: ProbeClass
    detail: str


@dataclass(frozen=True, slots=True)
class PlannedChain:
    """The steps to run, in order, and the ones the probe result removed."""

    steps: tuple[Step, ...]
    skipped: tuple[Step, ...]
    probe: ProbeResult | None


def parse_drivers(tokens: Sequence[str]) -> tuple[Step, ...]:
    """The chain a ``drivers`` list spells, in its order.

    Raises ``ValueError`` on an empty list, an unknown token or a duplicate.
    """
    if not tokens:
        raise ValueError("drivers: empty list")
    unknown = [token for token in tokens if token not in DRIVER_STEPS]
    if unknown:
        raise ValueError(f"drivers: unknown token {unknown[0]!r}")
    if len(set(tokens)) != len(tokens):
        raise ValueError("drivers: duplicate token")
    return tuple(DRIVER_STEPS[token] for token in tokens)


def format_drivers(steps: Sequence[Step]) -> list[str]:
    """The ``drivers`` tokens for ``steps``; the inverse of ``parse_drivers``.

    It only spells: a non-NTFS step gives a token ``parse_drivers`` and the
    registry check refuse (``"exfat"``), so a bad volume is refused on save.
    """
    return [_token(step) for step in steps]


def classify_probe(code: int | None, *, timed_out: bool, not_found: bool) -> ProbeClass:
    """The guard class of one probe outcome; anything unexpected is unsafe."""
    if timed_out or not_found or code is None:
        return ProbeClass.UNSAFE
    return PROBE_CLASSES.get(code, ProbeClass.UNSAFE)


def plan(steps: Sequence[Step], probe: ProbeResult | None) -> PlannedChain:
    """The steps that may run after ``probe``; the order never changes.

    ``probe`` None means no probe ran, which is right only for a chain without
    read-write steps; any kernel read-write step is then removed (fail closed).
    """
    klass = ProbeClass.UNSAFE if probe is None else probe.klass
    if klass is ProbeClass.HELD:
        return PlannedChain(steps=(), skipped=tuple(steps), probe=probe)
    if klass is ProbeClass.UNSAFE:
        return PlannedChain(
            steps=tuple(step for step in steps if step not in KERNEL_RW_STEPS),
            skipped=tuple(step for step in steps if step in KERNEL_RW_STEPS),
            probe=probe,
        )
    return PlannedChain(steps=tuple(steps), skipped=(), probe=probe)


def run_probe(ctx: "Context", device: str) -> ProbeResult:
    """Run ``ntfs-3g.probe --readwrite device`` once and classify it.

    ``device`` is ``/dev/<kname>``: it must be absolute, so it cannot be read
    as an option. The probe never resets ``$LogFile`` (it does not pass
    ``recover``), so running it changes nothing on the volume.
    """
    if not device.startswith("/"):
        raise ValueError(f"probe device must be an absolute path: {device!r}")
    argv = (ctx.platform.tools.ntfs3g_probe, "--readwrite", device)
    result = ctx.runner.run(Command(argv=argv, timeout=PROBE_TIMEOUT))
    klass = classify_probe(
        result.returncode, timed_out=result.timed_out, not_found=result.not_found
    )
    if result.timed_out:
        detail = f"{PROBE_NAME} timed out"
    elif result.not_found:
        detail = f"{PROBE_NAME} not found"
    else:
        detail = result.err_text().strip()
    log.info("%s %s: exit %s, %s", PROBE_NAME, device, result.returncode, klass)
    return ProbeResult(code=result.returncode, klass=klass, detail=detail)
