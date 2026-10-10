"""The NTFS chain: ``drivers`` spelling, the probe guard and chain planning.

Design Doc "NTFS Chain, Mount Options and Read-back" ("drivers Spelling",
"Guard and Planning") and ADR-0003 Decision 3. The probe codes are the ones
measured, not only the man page's:

- ``dirty.img`` (dirty flag only) and the real MEDIABOX: probe 0, so the
  kernel ``ntfs3`` rw step still runs (and the kernel refuses it);
- the real PERSONAL inner volume: probe 13 ("$MFTMirr does not match $MFT
  (record 3)"), unsafe; owner rule I006 keeps ``ntfs-3g`` rw, which refuses
  on its own, and the ``ntfs3`` ro step after it;
- 14 hibernated, 15 unclean ``$LogFile``, 16 held.

Anything the probe cannot answer (no exit status, timed out, not found) is
unsafe: fail closed for the kernel rw steps only (R-19).
"""

import logging

import pytest

from steamos_mounter.model import Driver, Mode, Step
from steamos_mounter.ntfs import (
    DEFAULT_CHAIN,
    DRIVER_STEPS,
    DRIVER_TOKENS,
    PROBE_TIMEOUT,
    PlannedChain,
    ProbeClass,
    ProbeResult,
    classify_probe,
    format_drivers,
    parse_drivers,
    plan,
    run_probe,
)
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture

PROBE = "/usr/bin/ntfs-3g.probe"
MEDIABOX_DEVICE = "/dev/sda5"
PERSONAL_DEVICE = "/dev/dm-0"
MFTMIRR_STDERR = b"$MFTMirr does not match $MFT (record 3).\n"

NTFS3_RW = Step(Driver.NTFS3, Mode.RW)
NTFS3_RO = Step(Driver.NTFS3, Mode.RO)
NTFS3G_RW = Step(Driver.NTFS3G, Mode.RW)
NTFS3G_RO = Step(Driver.NTFS3G, Mode.RO)
NTFS_RW = Step(Driver.NTFS, Mode.RW)
NTFS_RO = Step(Driver.NTFS, Mode.RO)
SPELLINGS = frozenset({"ntfs3", "ntfs-3g", "ntfs", "ntfs3:ro", "ntfs-3g:ro", "ntfs:ro"})
EVERY_STEP = (NTFS3_RW, NTFS3G_RW, NTFS_RW, NTFS3_RO, NTFS3G_RO, NTFS_RO)


def probe_result(klass: ProbeClass, code: int | None = 0) -> ProbeResult:
    return ProbeResult(code=code, klass=klass, detail="")


# --- drivers spelling ------------------------------------------------------


def test_default_chain_is_ntfs3_rw_then_ntfs3g_rw_then_ntfs3_ro():
    assert DEFAULT_CHAIN == (NTFS3_RW, NTFS3G_RW, NTFS3_RO)


def test_ntfs_never_default():
    """NFR-13, R-09: the kernel ``ntfs`` driver runs only when listed."""
    assert all(step.driver is not Driver.NTFS for step in DEFAULT_CHAIN)
    assert format_drivers(DEFAULT_CHAIN) == ["ntfs3", "ntfs-3g", "ntfs3:ro"]


def test_driver_tokens_are_the_six_spellings():
    assert DRIVER_TOKENS == SPELLINGS
    assert frozenset(DRIVER_STEPS) == DRIVER_TOKENS


@pytest.mark.parametrize(
    ("token", "step"),
    [
        ("ntfs3", NTFS3_RW),
        ("ntfs3:ro", NTFS3_RO),
        ("ntfs-3g", NTFS3G_RW),
        ("ntfs-3g:ro", NTFS3G_RO),
        ("ntfs", NTFS_RW),
        ("ntfs:ro", NTFS_RO),
    ],
)
def test_each_token_is_one_step(token, step):
    assert parse_drivers([token]) == (step,)
    assert format_drivers([step]) == [token]


def test_drivers_replace_chain():
    """AC-019: a ``drivers`` list is the whole chain, in its own order."""
    steps = parse_drivers(["ntfs-3g", "ntfs3:ro"])

    assert steps == (NTFS3G_RW, NTFS3_RO)
    assert plan(steps, probe_result(ProbeClass.SAFE)).steps == (NTFS3G_RW, NTFS3_RO)


def test_parse_drivers_keeps_the_listed_order():
    tokens = ["ntfs:ro", "ntfs3", "ntfs-3g:ro", "ntfs", "ntfs3:ro", "ntfs-3g"]

    assert parse_drivers(tokens) == (
        NTFS_RO,
        NTFS3_RW,
        NTFS3G_RO,
        NTFS_RW,
        NTFS3_RO,
        NTFS3G_RW,
    )


def test_format_drivers_inverts_parse_drivers():
    tokens = ["ntfs3:ro", "ntfs", "ntfs-3g"]

    assert format_drivers(parse_drivers(tokens)) == tokens


@pytest.mark.parametrize(
    "tokens",
    [
        ["ntfs-3g", "ntfs3g"],
        ["NTFS3"],
        ["ntfs3:rw"],
        ["ntfs3 "],
        ["fuseblk"],
        ["exfat"],
        [""],
    ],
)
def test_parse_drivers_rejects_an_unknown_token(tokens):
    with pytest.raises(ValueError, match="unknown"):
        parse_drivers(tokens)


def test_parse_drivers_rejects_a_duplicate_token():
    with pytest.raises(ValueError, match="duplicate"):
        parse_drivers(["ntfs3", "ntfs-3g", "ntfs3"])


def test_parse_drivers_rejects_an_empty_list():
    with pytest.raises(ValueError, match="empty"):
        parse_drivers([])


def test_format_drivers_spells_a_non_ntfs_step_that_parse_drivers_refuses():
    """The registry's save check refuses it as an unknown token."""
    tokens = format_drivers([Step(Driver.EXFAT, Mode.RW), Step(Driver.VFAT, Mode.RO)])

    assert tokens == ["exfat", "vfat:ro"]
    with pytest.raises(ValueError, match="unknown"):
        parse_drivers(tokens)


# --- classify_probe --------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "klass"),
    [
        (0, ProbeClass.SAFE),
        (15, ProbeClass.DIRTY),
        (14, ProbeClass.UNSAFE),
        (16, ProbeClass.HELD),
        (11, ProbeClass.UNSAFE),
        (12, ProbeClass.UNSAFE),
        (13, ProbeClass.UNSAFE),
        (17, ProbeClass.UNSAFE),
        (18, ProbeClass.UNSAFE),
        (19, ProbeClass.UNSAFE),
        (20, ProbeClass.UNSAFE),
        (21, ProbeClass.UNSAFE),
        (22, ProbeClass.UNSAFE),
        (1, ProbeClass.UNSAFE),
        (255, ProbeClass.UNSAFE),
        (-9, ProbeClass.UNSAFE),
    ],
)
def test_classification_table(code, klass):
    assert classify_probe(code, timed_out=False, not_found=False) is klass


def test_classify_missing_exit_status_is_unsafe():
    assert classify_probe(None, timed_out=False, not_found=False) is ProbeClass.UNSAFE


def test_classify_timed_out_probe_is_unsafe():
    assert classify_probe(None, timed_out=True, not_found=False) is ProbeClass.UNSAFE


def test_classify_missing_probe_is_unsafe():
    assert classify_probe(None, timed_out=False, not_found=True) is ProbeClass.UNSAFE


def test_classify_a_safe_code_with_a_timeout_flag_is_still_unsafe():
    """Fail closed: the flags win over a code that says safe."""
    assert classify_probe(0, timed_out=True, not_found=False) is ProbeClass.UNSAFE
    assert classify_probe(0, timed_out=False, not_found=True) is ProbeClass.UNSAFE


# --- plan ------------------------------------------------------------------


@pytest.mark.parametrize("klass", [ProbeClass.SAFE, ProbeClass.DIRTY])
def test_plan_safe_or_dirty_keeps_every_step(klass):
    probe = probe_result(klass)

    planned = plan(DEFAULT_CHAIN, probe)

    assert planned == PlannedChain(steps=DEFAULT_CHAIN, skipped=(), probe=probe)


def test_plan_unsafe_removes_kernel_rw_only():
    """AC-069, NFR-13: ``ntfs3`` and ``ntfs`` rw go; the rest stays in order."""
    probe = probe_result(ProbeClass.UNSAFE, code=14)

    planned = plan(EVERY_STEP, probe)

    assert planned.steps == (NTFS3G_RW, NTFS3_RO, NTFS3G_RO, NTFS_RO)
    assert planned.skipped == (NTFS3_RW, NTFS_RW)
    assert planned.probe is probe


def test_plan_unsafe_on_the_default_chain_keeps_ntfs3g_rw_then_ntfs3_ro():
    planned = plan(DEFAULT_CHAIN, probe_result(ProbeClass.UNSAFE, code=13))

    assert planned.steps == (NTFS3G_RW, NTFS3_RO)
    assert planned.skipped == (NTFS3_RW,)


def test_ntfs3g_only_list_on_unsafe_keeps_the_rw_step():
    """ADR-0003: ``drivers = ["ntfs-3g"]`` ends read-only by ntfs-3g's fallback."""
    planned = plan(parse_drivers(["ntfs-3g"]), probe_result(ProbeClass.UNSAFE, 14))

    assert planned.steps == (NTFS3G_RW,)
    assert planned.skipped == ()


def test_plan_held_runs_no_step():
    """AC-034: another component holds the volume; nothing mounts."""
    probe = probe_result(ProbeClass.HELD, code=16)

    planned = plan(DEFAULT_CHAIN, probe)

    assert planned == PlannedChain(steps=(), skipped=DEFAULT_CHAIN, probe=probe)


def test_plan_without_a_probe_keeps_a_read_only_chain():
    steps = (NTFS3_RO, NTFS3G_RO)

    assert plan(steps, None) == PlannedChain(steps=steps, skipped=(), probe=None)


def test_plan_without_a_probe_fails_closed_for_kernel_rw():
    """A rw chain planned with no probe result is treated as unsafe."""
    planned = plan(DEFAULT_CHAIN, None)

    assert planned.steps == (NTFS3G_RW, NTFS3_RO)
    assert planned.skipped == (NTFS3_RW,)
    assert planned.probe is None


# --- run_probe -------------------------------------------------------------


def test_run_probe_runs_readwrite_probe_once_with_the_20_second_timeout(
    ctx, fake_runner
):
    fake_runner.on(PROBE, Answer(returncode=0))

    result = run_probe(ctx, MEDIABOX_DEVICE)

    assert result == ProbeResult(code=0, klass=ProbeClass.SAFE, detail="")
    assert fake_runner.argvs == [(PROBE, "--readwrite", MEDIABOX_DEVICE)]
    assert fake_runner.calls[0].timeout == PROBE_TIMEOUT == 20.0


def test_run_probe_flag_is_in_the_deck_help_text():
    assert b"--readwrite" in load_fixture("ntfs-3g.probe-help.txt")


def test_dirty_flag_only_volume_probes_safe_and_keeps_ntfs3_rw(ctx, fake_runner):
    """Real MEDIABOX: dirty, probe 0; ntfs3 rw stays first (the kernel refuses)."""
    fake_runner.on(PROBE, Answer(returncode=0))

    planned = plan(DEFAULT_CHAIN, run_probe(ctx, MEDIABOX_DEVICE))

    assert planned.steps == DEFAULT_CHAIN
    assert planned.skipped == ()


def test_probe_13_corrupt_volume_skips_kernel_rw_keeps_ntfs3g_then_ntfs3_ro(
    ctx, fake_runner
):
    """Real PERSONAL inner volume, owner rule I006."""
    fake_runner.on(PROBE, Answer(returncode=13, stderr=MFTMIRR_STDERR))

    probe = run_probe(ctx, PERSONAL_DEVICE)
    planned = plan(DEFAULT_CHAIN, probe)

    assert probe == ProbeResult(
        code=13,
        klass=ProbeClass.UNSAFE,
        detail="$MFTMirr does not match $MFT (record 3).",
    )
    assert planned.steps == (NTFS3G_RW, NTFS3_RO)
    assert planned.skipped == (NTFS3_RW,)


@pytest.mark.parametrize(
    ("code", "klass"),
    [(15, ProbeClass.DIRTY), (14, ProbeClass.UNSAFE), (16, ProbeClass.HELD)],
)
def test_run_probe_classifies_the_exit_status(ctx, fake_runner, code, klass):
    fake_runner.on(PROBE, Answer(returncode=code))

    result = run_probe(ctx, MEDIABOX_DEVICE)

    assert (result.code, result.klass) == (code, klass)


def test_run_probe_timed_out_is_unsafe(ctx, fake_runner):
    fake_runner.on(PROBE, Answer.timeout())

    result = run_probe(ctx, MEDIABOX_DEVICE)

    assert result == ProbeResult(
        code=None, klass=ProbeClass.UNSAFE, detail="ntfs-3g.probe timed out"
    )


def test_run_probe_not_found_is_unsafe(ctx, fake_runner):
    fake_runner.on(PROBE, Answer.missing())

    result = run_probe(ctx, MEDIABOX_DEVICE)

    assert result == ProbeResult(
        code=None, klass=ProbeClass.UNSAFE, detail="ntfs-3g.probe not found"
    )


def test_run_probe_logs_the_code_and_class(ctx, fake_runner, caplog):
    fake_runner.on(PROBE, Answer(returncode=13, stderr=MFTMIRR_STDERR))

    with caplog.at_level(logging.INFO, logger="steamos_mounter.ntfs"):
        run_probe(ctx, PERSONAL_DEVICE)

    assert "ntfs-3g.probe /dev/dm-0: exit 13, unsafe" in caplog.text


@pytest.mark.parametrize("device", ["dm-0", "--readonly", ""])
def test_run_probe_refuses_a_device_that_is_not_an_absolute_path(
    ctx, fake_runner, device
):
    with pytest.raises(ValueError, match="absolute"):
        run_probe(ctx, device)

    assert fake_runner.calls == []
