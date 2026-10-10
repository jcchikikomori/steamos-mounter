"""The kernel log tap the NTFS chain reads refusal reasons from (DD-13).

ntfs3 explains a refused mount only in the kernel log, for example
``ntfs3(sdb5): volume is dirty and "force" flag is not set!``. A step marks
the log position before it runs and reads the lines printed after it.
``KernelLog`` is the seam: ``DevKmsg`` reads ``/dev/kmsg``; tests use
``tests/helpers/fake_kmsg.FakeKernelLog``.

``/dev/kmsg`` hands out one record per ``read``:
``<prio>,<seq>,<usec>,<flags>;<message>`` and then continuation lines that
start with a space. ``lseek(SEEK_END)`` moves past every record printed so
far, ``EAGAIN`` means nothing more is there yet, and ``EPIPE`` means records
were overwritten before they were read; the next read goes on after them.

Reading needs root, and ``build_context`` also builds a ``DevKmsg`` for the
``deck`` user's commands, so the device is opened on the first ``mark()``
only. An unreadable log is logged once and then gives no lines: the reason
falls back to the next source (IP-09).
"""

import logging
import os
from dataclasses import dataclass
from typing import Final, Protocol

from steamos_mounter.runner import TEXT_ERRORS

KMSG_PATH: Final = "/dev/kmsg"
# The kernel's limit for one record with its continuation lines
# (CONSOLE_EXT_LOG_MAX); a smaller buffer makes the read fail with EINVAL.
RECORD_MAX: Final = 8192
_HEADER_END: Final = b";"
_CONTINUATION: Final = b" "

log = logging.getLogger(__name__)


class KernelLog(Protocol):
    # mark: the current end of the log, taken right before a step.
    # lines_since: message texts printed after ``mark`` that start with
    # ``prefix`` (for example ``"ntfs3(sdb5):"``), oldest first.
    def mark(self) -> object: ...
    def lines_since(self, mark: object, *, prefix: str) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class _Mark:
    position: int  # index into DevKmsg._lines


class DevKmsg:
    """``KernelLog`` on ``/dev/kmsg``, opened ``O_RDONLY|O_NONBLOCK`` on first use.

    Messages read since the device was opened are kept in order, so every
    mark stays valid and ``lines_since`` can be asked again. ``path`` exists
    for tests, which point it at a regular file in the same format.
    """

    def __init__(self, *, path: str = KMSG_PATH) -> None:
        self._path = path
        self._fd: int | None = None
        self._failed = False
        self._lines: list[str] = []
        self._partial = b""

    def mark(self) -> _Mark:
        """Read what is pending, then seek to the end of the log."""
        if self._fd is None and not self._failed:
            self._open()
        else:
            self._read_pending()
        if self._fd is not None:
            self._seek_end(self._fd)
        return _Mark(len(self._lines))

    def lines_since(self, mark: object, *, prefix: str) -> tuple[str, ...]:
        if not isinstance(mark, _Mark):
            raise TypeError(f"not a DevKmsg mark: {mark!r}")
        self._read_pending()
        return tuple(
            line for line in self._lines[mark.position :] if line.startswith(prefix)
        )

    def _open(self) -> None:
        try:
            self._fd = os.open(self._path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as error:
            self._give_up(error)

    def _seek_end(self, fd: int) -> None:
        try:
            os.lseek(fd, 0, os.SEEK_END)
        except OSError as error:
            self._give_up(error)

    def _read_pending(self) -> None:
        """Take in every record printed since the last read."""
        while self._fd is not None:
            try:
                chunk = os.read(self._fd, RECORD_MAX)
            except BlockingIOError:  # EAGAIN: nothing more yet
                return
            except BrokenPipeError:  # EPIPE: the next read goes on after the gap
                log.debug("kernel log records were overwritten before they were read")
                continue
            except OSError as error:
                self._give_up(error)
                return
            if not chunk:  # end of a regular file standing in for the device
                return
            self._take(chunk)

    def _take(self, chunk: bytes) -> None:
        *complete, self._partial = (self._partial + chunk).split(b"\n")
        for line in complete:
            if line.startswith(_CONTINUATION):
                continue
            _header, found, message = line.partition(_HEADER_END)
            if found:
                self._lines.append(message.decode("utf-8", TEXT_ERRORS))

    def _give_up(self, error: OSError) -> None:
        log.warning("cannot read the kernel log %s: %s", self._path, error)
        self._failed = True
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
