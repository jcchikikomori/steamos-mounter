"""Output contract.

Design Doc: docs/design/steamos-mounter-design.md (Quality Assurance
Mechanisms, "Output contract tests": no ESC or control bytes in CLI and
installer output; exit codes distinct and documented; NFR-26: plain text, no
color, no cursor control). Every C0, DEL and C1 code point is pushed through
the real ``Output`` into real streams; no control character other than tab
may come out, apart from the newline that ends each line.

Extended later: state words and next steps (P2-T08), doctor lines (P5-T03).
"""

import io
import json
import unicodedata

import pytest

from steamos_mounter.errors import ExitCode
from steamos_mounter.output import Output

TAB = "\t"
C0 = [chr(code) for code in range(0x00, 0x20)]
DEL = "\x7f"
C1 = [chr(code) for code in range(0x80, 0xA0)]
EVERY_CONTROL = [*C0, DEL, *C1]
HOSTILE = "".join(EVERY_CONTROL)


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
