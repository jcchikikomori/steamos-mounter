"""Logging setup: journald's native protocol, the stderr fallback, redaction.

Every component logs through ``logging`` (ADR-COMMON-0001). ``setup_logging``
puts one handler on the root logger: ``JournalHandler`` when journald's socket
accepts a connection, otherwise a plain stderr handler (Docker tests, hosts
without systemd), the only intentional logging fallback. Each handler it
creates gets ``RedactingFilter`` as its first filter, so the message, the
traceback and every ``SM_*`` value are rendered and passed through
``sensitive.redact_text`` before anything formats them. Handler filters see
records from every logger; a filter on a package logger would miss records
propagated from its children (ADR-COMMON-0001 decision point 2).

Every entry carries ``SYSLOG_IDENTIFIER=steamos-mounter``, so
``journalctl -t steamos-mounter`` shows them all (AC-041); ``fields()`` adds
the per-volume ``SM_*`` fields used to narrow that view.
"""

import contextlib
import errno
import fcntl
import logging
import os
import socket
import struct
import sys
import traceback
from collections.abc import Iterable
from typing import Final, TextIO

from steamos_mounter.sensitive import redact_text

NOTICE: Final = 25
FIELD_PREFIX: Final = "SM_"
JOURNAL_SOCKET: Final = "/run/systemd/journal/socket"
IDENTIFIER: Final = "steamos-mounter"
# The record attribute ``fields()`` sets through ``extra=``.
FIELDS_ATTRIBUTE: Final = "sm_fields"
UNFORMATTABLE: Final = "log message could not be formatted"

logging.addLevelName(NOTICE, "NOTICE")

# syslog priority for each logging level and everything above it, highest first.
_PRIORITIES: Final = (
    (logging.CRITICAL, 2),
    (logging.ERROR, 3),
    (logging.WARNING, 4),
    (NOTICE, 5),
    (logging.INFO, 6),
)
_DEBUG_PRIORITY: Final = 7
_LENGTH: Final = struct.Struct("<Q")
# Lone surrogates (undecodable bytes from tool output) become visible \\udcXX
# text, so every value is valid UTF-8 and journalctl shows it as text.
_ENCODE_ERRORS: Final = "backslashreplace"
_MEMFD_NAME: Final = "steamos-mounter-journal"
_SEALS: Final = (
    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL
)


def fields(
    *,
    volume: str | None = None,
    uuid: str | None = None,
    device: str | None = None,
    event: str | None = None,
    state: str | None = None,
    reason: str | None = None,
    unit: str | None = None,
    step: str | None = None,
) -> dict[str, dict[str, str]]:
    """The ``extra=`` argument that adds the given values as ``SM_*`` fields."""
    named = {
        "VOLUME": volume,
        "UUID": uuid,
        "DEVICE": device,
        "EVENT": event,
        "STATE": state,
        "REASON": reason,
        "UNIT": unit,
        "STEP": step,
    }
    return {
        FIELDS_ATTRIBUTE: {
            FIELD_PREFIX + name: str(value)
            for name, value in named.items()
            if value is not None
        }
    }


def setup_logging(
    component: str,
    *,
    journal_socket: str = JOURNAL_SOCKET,
    stderr: TextIO | None = None,
) -> list[logging.Handler]:
    """Install the redacting handler on the root logger and return what it made.

    The root logger passes DEBUG, so command traces reach the journal.
    ``stderr`` defaults to ``sys.stderr`` as it is at setup time.
    """
    handler = _journal_or_stderr(component, journal_socket, stderr)
    handler.filters.insert(0, RedactingFilter())
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    return [handler]


class RedactingFilter(logging.Filter):
    """Leaves only redacted, fully rendered text on every record it passes.

    The message is rendered with its arguments and the traceback is formatted
    here, before redaction, because a formatter would otherwise render both
    later from the raw arguments and exception. Running it again on the same
    record (one record, several handlers) changes nothing.
    """

    _formatter = logging.Formatter()

    def filter(self, record: logging.LogRecord) -> bool:
        message = _render_message(record)
        if record.exc_info and not record.exc_text:
            record.exc_text = self._formatter.formatException(record.exc_info)
        record.msg = redact_text(message)
        record.args = None
        record.exc_info = None
        if record.exc_text:
            record.exc_text = redact_text(record.exc_text)
        if record.stack_info:
            record.stack_info = redact_text(record.stack_info)
        values = getattr(record, FIELDS_ATTRIBUTE, None)
        if values:
            redacted = {name: redact_text(str(text)) for name, text in values.items()}
            setattr(record, FIELDS_ATTRIBUTE, redacted)
        return True


class _RedactedErrorReport(logging.Handler):
    """``handleError`` that prints logging's stderr report redacted.

    A handler's own failure is raised while the caller may still be handling
    an exception (``log.exception`` inside ``except``), so the report's chain
    holds that exception's text, which can carry a live secret. The stock
    ``handleError`` prints it raw.
    """

    def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802 - stdlib hook
        if not logging.raiseExceptions or sys.stderr is None:
            return
        report = (
            f"--- Logging error ---\n{traceback.format_exc()}Message: {record.msg!r}\n"
        )
        # Same as logging: stderr is the last place to report to.
        with contextlib.suppress(OSError):
            sys.stderr.write(redact_text(report))


class JournalHandler(_RedactedErrorReport):
    """Sends each record to journald as one native-protocol datagram.

    An entry too large for a datagram (``EMSGSIZE``) is written to a sealed
    memfd and the descriptor is sent with an empty payload instead. Raises
    ``OSError`` when the socket does not accept a connection.
    """

    def __init__(self, component: str, socket_path: str = JOURNAL_SOCKET) -> None:
        journal = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            journal.connect(socket_path)
        except OSError:
            journal.close()
            raise
        super().__init__()
        self._socket = journal
        self._component = component

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._send(_encode(self._entry(record)))
        except Exception:  # noqa: BLE001 - logging's contract: report via handleError
            self.handleError(record)

    def close(self) -> None:
        self._socket.close()
        super().close()

    def _entry(self, record: logging.LogRecord) -> list[tuple[str, str]]:
        return [
            ("MESSAGE", self.format(record)),
            ("PRIORITY", str(_priority(record.levelno))),
            ("SYSLOG_IDENTIFIER", IDENTIFIER),
            ("CODE_FILE", record.pathname),
            ("CODE_LINE", str(record.lineno)),
            ("CODE_FUNC", str(record.funcName)),
            (FIELD_PREFIX + "COMPONENT", self._component),
            *getattr(record, FIELDS_ATTRIBUTE, {}).items(),
        ]

    def _send(self, data: bytes) -> None:
        try:
            self._socket.send(data)
        except OSError as error:
            if error.errno != errno.EMSGSIZE:
                raise
            self._send_sealed(data)

    def _send_sealed(self, data: bytes) -> None:
        descriptor = os.memfd_create(_MEMFD_NAME, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            with open(descriptor, "wb", closefd=False) as memfd:
                memfd.write(data)
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, _SEALS)
            socket.send_fds(self._socket, [], [descriptor])
        finally:
            os.close(descriptor)


class _StderrHandler(_RedactedErrorReport, logging.StreamHandler):
    """The stderr fallback: plain lines, the same redacted error report."""


class _StderrFormatter(logging.Formatter):
    """``steamos-mounter[<component>] LEVEL: message SM_X=value``, traceback below."""

    def __init__(self, component: str) -> None:
        super().__init__()
        self._component = component

    def formatMessage(self, record: logging.LogRecord) -> str:  # noqa: N802 - stdlib hook
        values = getattr(record, FIELDS_ATTRIBUTE, {})
        suffix = "".join(f" {name}={text}" for name, text in sorted(values.items()))
        return (
            f"{IDENTIFIER}[{self._component}] {record.levelname}: "
            f"{record.message}{suffix}"
        )


def _journal_or_stderr(
    component: str, journal_socket: str, stderr: TextIO | None
) -> logging.Handler:
    try:
        return JournalHandler(component, journal_socket)
    except OSError:
        handler = _StderrHandler(stderr)
        handler.setFormatter(_StderrFormatter(component))
        return handler


def _render_message(record: logging.LogRecord) -> str:
    """The message with its arguments; a broken format keeps only the template.

    Filters run outside a handler's error handling, so a format error raised
    here would reach the caller's log call. The arguments are left out: they
    are what failed to format, and the stock error report would print them raw.
    The template is redacted before ``repr``: escaping would turn a secret
    holding a backslash, a control character or a lone surrogate into text
    that no longer matches it.
    """
    try:
        return record.getMessage()
    except Exception:  # noqa: BLE001 - see docstring; the entry is still sent
        return f"{UNFORMATTABLE}: {redact_text(str(record.msg))!r}"


def _priority(level: int) -> int:
    for threshold, priority in _PRIORITIES:
        if level >= threshold:
            return priority
    return _DEBUG_PRIORITY


def _encode(entry: Iterable[tuple[str, str]]) -> bytes:
    """Native protocol: ``KEY=value\\n``, or ``KEY\\n<u64 LE size><value>\\n``.

    The one encoder for both the datagram and the memfd path.
    """
    parts: list[bytes] = []
    for name, value in entry:
        key = name.encode("ascii")
        data = value.encode("utf-8", _ENCODE_ERRORS)
        if b"\n" in data:
            parts += [key, b"\n", _LENGTH.pack(len(data)), data, b"\n"]
        else:
            parts += [key, b"=", data, b"\n"]
    return b"".join(parts)
