"""A ``KernelLog`` for tests, fed from the Deck's ntfs3 kernel lines.

Design Doc "Mock Boundary Decisions": reading ``/dev/kmsg`` needs root, so
tests use this fake. The real tap seeks to the end of the log on ``mark()``
and reads what the kernel printed after that during the step. The fake
models it with two lists:

- ``history``: lines already in the log; no ``mark`` ever returns them;
- pending lines (``pending=`` or ``queue``): released into the log by the
  next ``mark()``, so they read as printed during the step that follows.

``kernel_messages`` turns the capture ``journal-kernel-ntfs3.txt``
(``journalctl -k`` lines) into kernel message texts such as
``ntfs3(sdb5): volume is dirty and "force" flag is not set!``.
"""

from collections.abc import Iterable

from tests.helpers.fixtures import load_fixture

KERNEL_FIXTURE = "journal-kernel-ntfs3.txt"
# journalctl short-iso: "<time> <host> kernel: <message>".
KERNEL_TAG = " kernel: "


def kernel_messages(kname: str | None = None) -> tuple[str, ...]:
    """Message texts of the capture, oldest first; only ``kname``'s when given."""
    text = load_fixture(KERNEL_FIXTURE).decode("utf-8")
    messages = tuple(
        line.partition(KERNEL_TAG)[2]
        for line in text.splitlines()
        if KERNEL_TAG in line
    )
    if kname is None:
        return messages
    return tuple(m for m in messages if m.startswith(f"ntfs3({kname}):"))


class FakeKernelLog:
    """``mark`` returns a position in the log; queued lines follow it."""

    def __init__(
        self, *, history: Iterable[str] = (), pending: Iterable[str] = ()
    ) -> None:
        self._log: list[str] = list(history)
        self._pending: list[str] = list(pending)

    def queue(self, *lines: str) -> None:
        """Lines the kernel prints during the step after the next ``mark``."""
        self._pending.extend(lines)

    def mark(self) -> int:
        position = len(self._log)
        self._log.extend(self._pending)
        self._pending.clear()
        return position

    def lines_since(self, mark: object, *, prefix: str) -> tuple[str, ...]:
        if not isinstance(mark, int):
            raise TypeError(f"not a FakeKernelLog mark: {mark!r}")
        return tuple(line for line in self._log[mark:] if line.startswith(prefix))
