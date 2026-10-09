"""The only module that writes to the terminal.

Plain lines with no color and no cursor control (NFR-26): ``line`` and
``error`` drop ESC and every other C0 control, DEL and every C1 control,
keeping only tab. Stripping the ESC byte alone is enough to defuse an escape
sequence; the printable rest of it (``[31m``) is shown as-is. ``json`` keeps
the data intact and writes those characters as ``\\uXXXX`` escapes instead.
"""

import json
import sys
from typing import TextIO

ERROR_PREFIX = "steamos-mounter: "
JSON_INDENT = 2

_TAB = 0x09
_DEL = 0x7F
_CONTROL_CODE_POINTS = (*range(0x00, 0x20), _DEL, *range(0x80, 0xA0))
# json.dumps already escapes C0 inside strings; DEL and C1 pass through raw
# when ensure_ascii is off, so they are escaped here.
_JSON_RAW_CONTROLS = (_DEL, *range(0x80, 0xA0))

_STRIP_CONTROLS = {code: None for code in _CONTROL_CODE_POINTS if code != _TAB}
_ESCAPE_JSON_CONTROLS = {code: f"\\u{code:04x}" for code in _JSON_RAW_CONTROLS}


def _plain(text: str) -> str:
    return text.translate(_STRIP_CONTROLS)


class Output:
    """Writes plain lines to stdout, errors to stderr and JSON to stdout.

    Streams default to the process's ``sys.stdout`` and ``sys.stderr`` as they
    are at write time.
    """

    def __init__(self, out: TextIO | None = None, err: TextIO | None = None) -> None:
        self._out = out
        self._err = err

    def line(self, text: str) -> None:
        self._stdout().write(_plain(text) + "\n")

    def error(self, text: str) -> None:
        self._stderr().write(ERROR_PREFIX + _plain(text) + "\n")

    def json(self, payload: object) -> None:
        document = json.dumps(
            payload, sort_keys=True, ensure_ascii=False, indent=JSON_INDENT
        )
        self._stdout().write(document.translate(_ESCAPE_JSON_CONTROLS) + "\n")

    def _stdout(self) -> TextIO:
        return sys.stdout if self._out is None else self._out

    def _stderr(self) -> TextIO:
        return sys.stderr if self._err is None else self._err
