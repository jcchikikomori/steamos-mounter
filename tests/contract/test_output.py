"""Output contract.

Design Doc: docs/design/steamos-mounter-design.md (Quality Assurance
Mechanisms, "Output contract tests": no ESC or control bytes in CLI and
installer output; exit codes distinct and documented; NFR-26: plain text, no
color, no cursor control). Every C0, DEL and C1 code point is pushed through
the real ``Output`` into real streams; no control character other than tab
may come out, apart from the newline that ends each line.

State words and next steps (P2-T08, Design Doc "list and scan Output", UI
metrics 1 and 2): every ``VolumeState``, with no reason and with every reason
code ``state`` knows, renders words, and a next step for every non-healthy
state; the rendered ``list`` block carries no ESC byte and no color, even when
the volume name is hostile. Installer lines (P4-T06): every ``install`` and
``uninstall`` line starts with its own prefix and carries no control
character, whatever a step's detail holds. Extended later: doctor lines
(P5-T03).
"""

import io
import json
import unicodedata

import pytest

from steamos_mounter import installer, state
from steamos_mounter.errors import ExitCode
from steamos_mounter.installer_report import InstallReport, StepLine
from steamos_mounter.model import VolumeState
from steamos_mounter.output import Output
from tests.helpers.cli_env import run_cli, steamos_host

TAB = "\t"
C0 = [chr(code) for code in range(0x00, 0x20)]
DEL = "\x7f"
C1 = [chr(code) for code in range(0x80, 0xA0)]
EVERY_CONTROL = [*C0, DEL, *C1]
HOSTILE = "".join(EVERY_CONTROL)
ESC = "\x1b"
CLI = "sudo /opt/steamos-mounter/bin/steamos-mounter"
HEALTHY = frozenset({VolumeState.MOUNTED_RW})
NO_STEP = "-"
# The reason codes the Design Doc names, per state; state.py must know them all.
DESIGN_REASONS = {
    VolumeState.NEEDS_KEY: {
        "stored_key_missing",
        "stored_key_rejected",
        "no_session",
        "session_not_sure",
        "dialog_open",
        "dialog_failed",
        "key_permissions",
    },
    VolumeState.MOUNT_FAILED: {
        "fstype_mismatch",
        "device_busy",
        "no_free_name",
        "probe_failed",
        "registry_entry_invalid",
        "os_partition",
    },
    VolumeState.MOUNTED_RO: {"unsafe"},
    VolumeState.MOUNTED_RW_DIRTY: {"dirty"},
    VolumeState.NOT_MOUNTED: {"no_partition_instance"},
}


def state_reason_pairs() -> list[tuple[VolumeState, str | None]]:
    pairs: list[tuple[VolumeState, str | None]] = [(item, None) for item in VolumeState]
    for item, reasons in state.KNOWN_REASONS.items():
        pairs.extend((item, reason) for reason in sorted(reasons))
    return pairs


def pair_id(pair: tuple[VolumeState, str | None]) -> str:
    item, reason = pair
    return f"{item.value}-{reason or 'none'}"


def render_block(item: VolumeState, reason: str | None, name: str) -> str:
    """A ``list`` text block for one volume, written through the real ``Output``."""
    out = io.StringIO()
    output = Output(out=out, err=io.StringIO())
    output.line(name)
    output.line(f"  state:   {state.words(item, reason)}")
    warning = state.warning(item, reason, name=name)
    output.line(f"  warning: {warning or NO_STEP}")
    output.line(f"  next:    {state.next_step(item, reason, name=name, cli_root=CLI)}")
    return out.getvalue()


def control_characters(text: str) -> set[str]:
    return {char for char in text if unicodedata.category(char) == "Cc"}


def test_every_control_code_point_is_covered():
    assert len(EVERY_CONTROL) == 65
    assert {char for char in EVERY_CONTROL if unicodedata.category(char) == "Cc"} == (
        set(EVERY_CONTROL)
    )


@pytest.mark.parametrize("char", EVERY_CONTROL, ids=lambda char: f"U+{ord(char):04X}")
def test_no_control_character_but_tab_survives_line(char):
    out = io.StringIO()

    Output(out=out, err=io.StringIO()).line(f"label{char}name")

    expected = "label\tname\n" if char == TAB else "labelname\n"
    assert out.getvalue() == expected


def test_line_output_has_no_esc_and_no_controls_but_tab_and_the_final_newline():
    out = io.StringIO()

    Output(out=out, err=io.StringIO()).line(f"\x1b[2J\x1b]8;;x\x07{HOSTILE}end")

    text = out.getvalue()
    assert "\x1b" not in text
    assert control_characters(text.removesuffix("\n")) == {TAB}
    assert text.endswith("end\n")
    assert text.count("\n") == 1


def test_error_output_has_no_controls_but_tab_and_the_final_newline():
    err = io.StringIO()

    Output(out=io.StringIO(), err=err).error(f"bad{HOSTILE}label")

    text = err.getvalue()
    assert text.startswith("steamos-mounter: bad")
    assert control_characters(text.removesuffix("\n")) == {TAB}
    assert text.count("\n") == 1


def test_json_output_carries_controls_only_as_escapes():
    out = io.StringIO()

    Output(out=out, err=io.StringIO()).json({"label": HOSTILE})

    text = out.getvalue()
    assert control_characters(text) <= {"\n"}
    assert json.loads(text) == {"label": HOSTILE}


def test_exit_codes_are_distinct_and_numbered_zero_to_eight():
    values = [member.value for member in ExitCode]

    assert len(values) == len(set(values))
    assert sorted(values) == list(range(9))


# --- state words and next steps (P2-T08) ----------------------------------------------


def test_state_knows_every_reason_the_design_names():
    for item, reasons in DESIGN_REASONS.items():
        assert reasons <= set(state.KNOWN_REASONS.get(item, ()))


@pytest.mark.parametrize("pair", state_reason_pairs(), ids=pair_id)
def test_every_state_and_reason_renders_words(pair):
    item, reason = pair

    text = state.words(item, reason)

    assert text.strip()
    assert ESC not in text
    assert control_characters(text) == set()


@pytest.mark.parametrize("pair", state_reason_pairs(), ids=pair_id)
def test_every_non_healthy_state_and_reason_renders_a_next_step(pair):
    item, reason = pair

    step = state.next_step(item, reason, name="MEDIABOX", cli_root=CLI)

    assert ESC not in step
    assert control_characters(step) == set()
    if item in HEALTHY:
        assert step == NO_STEP
    else:
        assert step not in ("", NO_STEP)


@pytest.mark.parametrize("pair", state_reason_pairs(), ids=pair_id)
def test_list_block_has_no_esc_and_no_color_even_for_a_hostile_name(pair):
    item, reason = pair

    text = render_block(item, reason, f"\x1b[31mRED{HOSTILE}NAME")

    assert ESC not in text
    assert control_characters(text) <= {TAB, "\n"}
    assert "[31m" in text  # only the ESC byte is dropped; the rest stays visible
    assert text.count("\n") == 4


@pytest.mark.parametrize("command", ["install", "uninstall"])
def test_installer_lines_carry_their_prefix_and_no_controls(
    ctx, tmp_path, monkeypatch, command
):
    steamos_host(tmp_path)
    statuses = ("ok", "skipped", "busy", "failed")
    report = InstallReport(
        tuple(
            StepLine(f"step{HOSTILE}", status, f"{ESC}[31mdetail{HOSTILE}")
            for status in statuses
        ),
        ExitCode.PARTIAL,
    )
    monkeypatch.setattr(installer, command, lambda *_args, **_kwargs: report)

    result = run_cli(ctx, command)

    lines = result.out.splitlines()
    assert result.code == ExitCode.PARTIAL
    assert result.err == ""
    assert [line.split(": ")[2] for line in lines] == list(statuses)
    assert all(line.startswith(f"steamos-mounter {command}: step") for line in lines)
    assert ESC not in result.out
    assert control_characters(result.out.replace("\n", "")) == {TAB}
