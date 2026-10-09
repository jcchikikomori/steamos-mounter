"""Unit tests for steamos_mounter.output.

Design Doc: docs/design/steamos-mounter-design.md (sections "Module
Responsibilities and Public Interfaces > errors, output, sensitive" and
"CLI Contract", rule 3: plain lines, no color, no cursor control, errors as
one ``steamos-mounter:`` line on stderr). Real strings, no fakes: the streams
are StringIO objects or pytest's captured sys.stdout/sys.stderr.
"""

import io
import json

import pytest

from steamos_mounter.output import Output


def make_output() -> tuple[Output, io.StringIO, io.StringIO]:
    out = io.StringIO()
    err = io.StringIO()
    return Output(out=out, err=err), out, err


def test_line_writes_plain_text_and_one_newline_to_stdout():
    output, out, err = make_output()

    output.line("MEDIABOX  mounted read-write")

    assert out.getvalue() == "MEDIABOX  mounted read-write\n"
    assert err.getvalue() == ""


def test_line_removes_esc_so_color_codes_cannot_reach_the_terminal():
    output, out, _ = make_output()

    output.line("\x1b[31mred\x1b[0m label")

    assert out.getvalue() == "[31mred[0m label\n"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a\x00b", "ab\n"),
        ("bell\x07", "bell\n"),
        ("two\nlines", "twolines\n"),
        ("carriage\rreturn", "carriagereturn\n"),
        ("unit\x1fsep", "unitsep\n"),
        ("del\x7f", "del\n"),
        ("c1\x80start", "c1start\n"),
        ("csi\x9b31m", "csi31m\n"),
        ("c1\x9fend", "c1end\n"),
    ],
)
def test_line_strips_c0_del_and_c1_controls(text, expected):
    output, out, _ = make_output()

    output.line(text)

    assert out.getvalue() == expected


def test_line_keeps_tab():
    output, out, _ = make_output()

    output.line("name\tpath")

    assert out.getvalue() == "name\tpath\n"


def test_line_keeps_non_ascii_text_just_outside_the_c1_range():
    output, out, _ = make_output()

    output.line("\xa0Spiele été 日本 \U0001f3ae ~")

    assert out.getvalue() == "\xa0Spiele été 日本 \U0001f3ae ~\n"


def test_line_with_empty_text_writes_an_empty_line():
    output, out, _ = make_output()

    output.line("")

    assert out.getvalue() == "\n"


def test_error_writes_one_prefixed_line_to_stderr_only():
    output, out, err = make_output()

    output.error("volume MEDIABOX is not attached. Plug it in and retry")

    assert err.getvalue() == (
        "steamos-mounter: volume MEDIABOX is not attached. Plug it in and retry\n"
    )
    assert out.getvalue() == ""


def test_error_strips_controls_like_line():
    output, _, err = make_output()

    output.error("bad label \x1b]0;title\x07\nnext")

    assert err.getvalue() == "steamos-mounter: bad label ]0;titlenext\n"


def test_json_writes_one_document_with_sorted_keys():
    output, out, err = make_output()

    output.json({"volumes": [], "format": 1})

    text = out.getvalue()
    assert text.index('"format"') < text.index('"volumes"')
    assert text.endswith("}\n")
    assert json.loads(text) == {"format": 1, "volumes": []}
    assert err.getvalue() == ""


def test_json_sorts_nested_keys_too():
    output, out, _ = make_output()

    output.json({"volume": {"uuid": "1234", "label": "GAMES"}})

    text = out.getvalue()
    assert text.index('"label"') < text.index('"uuid"')


def test_json_keeps_non_ascii_unescaped():
    output, out, _ = make_output()

    output.json({"label": "été 日本"})

    assert '"été 日本"' in out.getvalue()
    assert "\\u00e9" not in out.getvalue()


def test_json_escapes_controls_so_the_raw_bytes_never_reach_the_terminal():
    output, out, _ = make_output()

    output.json({"label": "a\x1bb\x7fc\x9bd\te"})

    text = out.getvalue()
    for raw in ("\x1b", "\x7f", "\x9b", "\t"):
        assert raw not in text
    assert json.loads(text) == {"label": "a\x1bb\x7fc\x9bd\te"}


def test_json_rejects_a_payload_that_is_not_json():
    output, out, _ = make_output()

    with pytest.raises(TypeError):
        output.json({"when": object()})
    assert out.getvalue() == ""


def test_default_streams_are_the_process_stdout_and_stderr(capsys):
    output = Output()

    output.line("to stdout")
    output.error("to stderr")
    output.json([1])

    captured = capsys.readouterr()
    assert captured.out.startswith("to stdout\n")
    assert json.loads(captured.out.removeprefix("to stdout\n")) == [1]
    assert captured.err == "steamos-mounter: to stderr\n"
