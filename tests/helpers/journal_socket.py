"""A real journald stand-in: an ``AF_UNIX``/``SOCK_DGRAM`` socket under tmp_path.

Design Doc "Mock Boundary Decisions": the journald socket is not faked. Tests
bind a real datagram socket in ``tmp_path`` and decode every entry the package
sends, so the wire format and the sealed-memfd path are proven against the
kernel. The decoder is written from the journal native protocol
(https://systemd.io/JOURNAL_NATIVE_PROTOCOL/), not from the package:
``KEY=value\\n`` for single-line values, ``KEY\\n<u64 LE length><value>\\n``
for the rest; an entry too large for one datagram arrives as an empty
datagram carrying one memfd.

A background thread reads the socket the whole time, as journald does. The
kernel queues at most ``net.unix.max_dgram_qlen`` datagrams (10 in Docker),
and the package's socket blocks when that queue is full, so a receiver that
only read on demand would hang a test that logs more than ten entries.

Anything the reader fails on, a datagram it cannot decode or a failed read, is
queued in its place, so ``drain`` raises the real cause instead of timing out.
"""

import fcntl
import os
import queue
import re
import socket
import struct
import threading
from dataclasses import dataclass
from pathlib import Path

LENGTH = struct.Struct("<Q")
# Above the default send buffer (212992), the largest datagram a sender gets out.
MAX_DATAGRAM = 1 << 18
MAX_FDS = 4
ALL_SEALS = (
    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL
)
# journald's rule for field names a client may send.
FIELD_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
# Passing runs never wait this long; a host deep in swap can get close.
TIMEOUT = 30.0
# Control datagrams the receiver sends to itself. A NUL first byte can never
# start a field name, so no entry is mistaken for one.
_SYNC = b"\x00sync"
_STOP = b"\x00stop"
_SYNCED = object()
# Queued when the reader exits; it stays last in the queue from then on.
_STOPPED = object()


def decode_entry(data: bytes) -> dict[str, str]:
    """The fields of one entry.

    A missing newline or length, a bad terminator, a field name journald would
    refuse, or a repeated field raises ValueError.
    """
    fields: dict[str, str] = {}
    position = 0
    while position < len(data):
        end = data.find(b"\n", position)
        if end < 0:
            raise ValueError("field without a terminating newline")
        line = data[position:end]
        if b"=" in line:
            name, _, value = line.partition(b"=")
            position = end + 1
        else:
            name = line
            try:
                (size,) = LENGTH.unpack_from(data, end + 1)
            except struct.error as error:
                raise ValueError(f"field {name!r} has a truncated length") from error
            start = end + 1 + LENGTH.size
            value = data[start : start + size]
            if data[start + size : start + size + 1] != b"\n":
                raise ValueError(f"length-prefixed field {name!r} is not terminated")
            position = start + size + 1
        key = name.decode("ascii", "replace")
        if not FIELD_NAME.fullmatch(key):
            raise ValueError(f"invalid field name {name!r}")
        if key in fields:
            raise ValueError(f"repeated field {key}")
        fields[key] = value.decode("utf-8")
    return fields


@dataclass(frozen=True, slots=True)
class Entry:
    """One received entry: its bytes, and how they arrived."""

    payload: bytes
    via_memfd: bool
    seals: int | None

    @property
    def fields(self) -> dict[str, str]:
        return decode_entry(self.payload)


class JournalReceiver:
    """Binds ``path``, reads it on a thread and hands back entries in order."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._socket.bind(str(path))
        self._received: queue.Queue[object] = queue.Queue()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def drain(self) -> list[Entry]:
        """Every entry received so far, in arrival order.

        Sends are synchronous, so every entry logged before this call is
        already queued in the kernel. A sync datagram queued behind them marks
        the end: once the reader reaches it, it has read them all. A failure
        is raised only after that mark, so the next drain starts clean; the
        first failure is the one raised.
        """
        if self._reader.is_alive():
            self._send_control(_SYNC)
        entries: list[Entry] = []
        failure: Exception | None = None
        while True:
            try:
                item = self._received.get(timeout=TIMEOUT)
            except queue.Empty:
                raise AssertionError("journal receiver did not catch up") from failure
            if item is _SYNCED:
                break
            if item is _STOPPED:
                self._received.put(_STOPPED)
                if failure is None:
                    raise AssertionError("journal receiver stopped reading")
                break
            if isinstance(item, Exception):
                failure = failure or item
                continue
            entries.append(item)
        if failure is not None:
            raise failure
        return entries

    def one(self) -> Entry:
        """The single queued entry; anything else is an error."""
        entries = self.drain()
        if len(entries) != 1:
            raise AssertionError(f"expected one journal entry, got {len(entries)}")
        return entries[0]

    def close(self) -> None:
        if self._reader.is_alive():
            self._send_control(_STOP)
            self._reader.join(TIMEOUT)
        self._socket.close()

    def _send_control(self, message: bytes) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
            client.settimeout(TIMEOUT)
            client.sendto(message, str(self.path))

    def _read(self) -> None:
        try:
            self._read_until_stopped()
        finally:
            self._received.put(_STOPPED)

    def _read_until_stopped(self) -> None:
        while True:
            try:
                message, fds, flags, _ = socket.recv_fds(
                    self._socket, MAX_DATAGRAM, MAX_FDS
                )
            except Exception as error:  # noqa: BLE001 - handed to drain
                self._received.put(error)
                return
            if not fds and message == _STOP:
                return
            if not fds and message == _SYNC:
                self._received.put(_SYNCED)
                continue
            try:
                self._received.put(_entry(message, fds, flags))
            except Exception as error:  # noqa: BLE001 - handed to drain
                self._received.put(error)


def _entry(message: bytes, fds: list[int], flags: int) -> Entry:
    try:
        if flags & socket.MSG_TRUNC:
            raise ValueError("datagram larger than the receive buffer")
        if flags & socket.MSG_CTRUNC:
            raise ValueError("ancillary data truncated: too many descriptors")
        if not fds:
            return Entry(message, via_memfd=False, seals=None)
        if message or len(fds) != 1:
            raise ValueError("a memfd entry is one descriptor and an empty payload")
        (descriptor,) = fds
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
        size = os.fstat(descriptor).st_size
        return Entry(os.pread(descriptor, size, 0), via_memfd=True, seals=seals)
    finally:
        for descriptor in fds:
            os.close(descriptor)
