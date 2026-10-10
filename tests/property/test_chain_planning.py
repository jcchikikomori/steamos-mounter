"""Chain planning never reorders, never adds, and never lets the kernel write unsafe.

Design Doc "Guard and Planning", ADR-0003 Decision 3, NFR-13 and R-19. For any
``drivers`` chain (any non-empty, duplicate-free list of the six steps) and any
probe outcome, including no probe at all:

- the planned steps are a subsequence of the input, so the order never changes
  and no step is added;
- planned plus skipped steps are exactly the input steps;
- with ``unsafe`` (or no probe), no kernel read-write step remains, and every
  other step does;
- with ``held``, nothing remains;
- with ``safe`` or ``dirty``, everything remains.

Runs are reproducible: ``derandomize=True`` and no example database.
"""

from collections.abc import Sequence

from hypothesis import given, settings
from hypothesis import strategies as st

from steamos_mounter.model import Driver, Mode, Step
from steamos_mounter.ntfs import ProbeClass, ProbeResult, plan

NTFS_STEPS = tuple(
    Step(driver, mode)
    for driver in (Driver.NTFS3, Driver.NTFS3G, Driver.NTFS)
    for mode in Mode
)
KERNEL_RW = frozenset({Step(Driver.NTFS3, Mode.RW), Step(Driver.NTFS, Mode.RW)})

PROPERTY_SETTINGS = settings(
    derandomize=True, database=None, max_examples=300, deadline=None
)

chains = st.lists(st.sampled_from(NTFS_STEPS), min_size=1, unique=True).map(tuple)
codes = st.none() | st.integers(min_value=-64, max_value=255)
probes = st.none() | st.builds(
    ProbeResult,
    code=codes,
    klass=st.sampled_from(ProbeClass),
    detail=st.text(max_size=20),
)
unsafe_or_missing = st.none() | st.builds(
    ProbeResult, code=codes, klass=st.just(ProbeClass.UNSAFE), detail=st.just("")
)


def is_subsequence(part: Sequence[Step], whole: Sequence[Step]) -> bool:
    remaining = iter(whole)
    return all(step in remaining for step in part)


@PROPERTY_SETTINGS
@given(steps=chains, probe=probes)
def test_planned_steps_are_a_subsequence_of_the_input(steps, probe):
    planned = plan(steps, probe)

    assert is_subsequence(planned.steps, steps)
    assert is_subsequence(planned.skipped, steps)
    assert sorted(planned.steps + planned.skipped, key=steps.index) == list(steps)
    assert planned.probe is probe


@PROPERTY_SETTINGS
@given(steps=chains, probe=unsafe_or_missing)
def test_unsafe_or_missing_probe_leaves_no_kernel_rw_step(steps, probe):
    planned = plan(steps, probe)

    assert not KERNEL_RW.intersection(planned.steps)
    assert planned.steps == tuple(step for step in steps if step not in KERNEL_RW)


@PROPERTY_SETTINGS
@given(steps=chains, code=codes)
def test_held_leaves_nothing(steps, code):
    planned = plan(steps, ProbeResult(code=code, klass=ProbeClass.HELD, detail=""))

    assert planned.steps == ()
    assert planned.skipped == steps


@PROPERTY_SETTINGS
@given(
    steps=chains,
    klass=st.sampled_from((ProbeClass.SAFE, ProbeClass.DIRTY)),
)
def test_safe_or_dirty_keeps_every_step(steps, klass):
    planned = plan(steps, ProbeResult(code=0, klass=klass, detail=""))

    assert planned.steps == steps
    assert planned.skipped == ()
