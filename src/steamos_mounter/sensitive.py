"""The secret wrapper and the live-secret registry used for redaction.

Key bytes live only inside ``SecretBytes`` from the moment they are read until
they are written to cryptsetup's stdin or the key file (ADR-COMMON-0001
decision 4, ADR-0004). Every text form of the wrapper is a fixed placeholder,
and it refuses pickling and copying, so a key cannot reach a log, a record or
a file by accident.

Each wrapper registers itself as live until ``clear()``. ``redact_text``
replaces every live secret in a string; the logging setup runs it in every
handler. The registry holds strong references on purpose: a secret nobody
cleared stays redacted rather than slipping out of the set when it is
garbage-collected.
"""

from typing import NoReturn

PLACEHOLDER = "<secret redacted>"
REDACTED = "[REDACTED]"
DEFAULT_LABEL = "key"
# Text that came from bytes with the same error handler (subprocess output)
# holds undecodable bytes as lone surrogates; decoding the secret the same way
# lets those match too. Valid UTF-8 decodes identically under either handler.
_TEXT_ERRORS = "surrogateescape"

_LIVE: dict[int, "SecretBytes"] = {}


class SecretBytes:
    """Holds key bytes in a ``bytearray`` that ``clear()`` zeroes in place."""

    __slots__ = ("_buffer", "_label")

    def __init__(self, data: bytes | bytearray, *, label: str = DEFAULT_LABEL) -> None:
        if not isinstance(data, bytes | bytearray):
            raise TypeError("SecretBytes takes bytes or bytearray")
        self._buffer = bytearray(data)
        self._label = label
        _LIVE[id(self)] = self

    @property
    def label(self) -> str:
        """What the secret is (``key``, ``recovery``), safe to log."""
        return self._label

    def reveal(self) -> bytes:
        """The bytes, only for cryptsetup's stdin and the key file write."""
        if id(self) not in _LIVE:
            raise ValueError("secret was cleared")
        return bytes(self._buffer)

    def clear(self) -> None:
        """Zero the buffer in place and unregister; calling it again is a no-op."""
        self._buffer[:] = bytes(len(self._buffer))
        self._buffer = bytearray()
        _LIVE.pop(id(self), None)

    def __len__(self) -> int:
        return len(self._buffer)

    def __enter__(self) -> "SecretBytes":
        return self

    def __exit__(self, *exc: object) -> None:
        self.clear()

    def __str__(self) -> str:
        return PLACEHOLDER

    def __repr__(self) -> str:
        return PLACEHOLDER

    def __format__(self, format_spec: str) -> str:
        return PLACEHOLDER

    def __reduce__(self) -> NoReturn:
        raise TypeError("SecretBytes cannot be pickled or copied")


def live_secrets() -> tuple[bytes, ...]:
    """The bytes of every secret not yet cleared, oldest first."""
    return tuple(bytes(secret._buffer) for secret in tuple(_LIVE.values()))


def redact_text(text: str) -> str:
    """Replace every live secret in ``text`` with ``[REDACTED]``.

    Longer secrets go first, so a secret that contains another is replaced
    whole instead of leaving its tail behind. Empty secrets are skipped.
    """
    needles = [
        secret._buffer.decode("utf-8", _TEXT_ERRORS)
        for secret in tuple(_LIVE.values())
        if secret._buffer
    ]
    for needle in sorted(needles, key=len, reverse=True):
        text = text.replace(needle, REDACTED)
    return text
