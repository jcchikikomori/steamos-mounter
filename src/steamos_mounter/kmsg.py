"""The kernel log tap the NTFS chain reads refusal reasons from (DD-13).

ntfs3 explains a refused mount only in the kernel log, for example
``ntfs3(sdb5): volume is dirty and "force" flag is not set!``. A step marks
the log position before it runs and reads the lines printed after it.
``KernelLog`` is the seam: tests use ``tests/helpers/fake_kmsg.FakeKernelLog``.
The ``/dev/kmsg`` implementation, ``DevKmsg``, lands with the NTFS chain.
"""

from typing import Protocol


class KernelLog(Protocol):
    # mark: the current end of the log, taken right before a step.
    # lines_since: message texts printed after ``mark`` that start with
    # ``prefix`` (for example ``"ntfs3(sdb5):"``), oldest first.
    def mark(self) -> object: ...
    def lines_since(self, mark: object, *, prefix: str) -> tuple[str, ...]: ...
