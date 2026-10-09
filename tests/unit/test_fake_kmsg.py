"""Self-tests for ``FakeKernelLog``, the ``/dev/kmsg`` stand-in.

Design Doc "Mock Boundary Decisions" and DD-13: the real tap seeks to the end
of ``/dev/kmsg`` before a step (``mark``) and reads what the kernel printed
after it. The fake releases queued lines at the next ``mark``, so they count
as printed during the step that follows.
"""

import pytest

from steamos_mounter.kmsg import KernelLog
from tests.helpers.fake_kmsg import FakeKernelLog, kernel_messages

DIRTY = 'ntfs3(sdb5): volume is dirty and "force" flag is not set!'
CHKDSK = "ntfs3(sdb5): It is recommended to use chkdsk."
DM0_DIRTY = 'ntfs3(dm-0): volume is dirty and "force" flag is not set!'


def test_kernel_messages_strips_the_journal_prefix():
    messages = kernel_messages()

    assert len(messages) == 14
    assert messages[:2] == (CHKDSK, DIRTY)
    assert all(message.startswith("ntfs3(") for message in messages)


def test_kernel_messages_filters_by_kname():
    assert set(kernel_messages("dm-0")) == {
        "ntfs3(dm-0): It is recommended to use chkdsk.",
        DM0_DIRTY,
    }
    assert len(kernel_messages("sdb5")) == 8


def test_queued_lines_are_released_after_the_next_mark():
    log = FakeKernelLog()
    log.queue(CHKDSK, DIRTY)

    mark = log.mark()

    assert log.lines_since(mark, prefix="ntfs3(sdb5):") == (CHKDSK, DIRTY)


def test_history_is_not_seen_after_a_mark():
    log = FakeKernelLog(history=[DIRTY])

    mark = log.mark()

    assert log.lines_since(mark, prefix="ntfs3(sdb5):") == ()


def test_lines_since_filters_by_prefix():
    log = FakeKernelLog(pending=[DM0_DIRTY, DIRTY])

    mark = log.mark()

    assert log.lines_since(mark, prefix="ntfs3(dm-0):") == (DM0_DIRTY,)


def test_lines_are_released_once():
    log = FakeKernelLog(pending=[DIRTY])
    first = log.mark()

    second = log.mark()

    assert log.lines_since(first, prefix="ntfs3(") == (DIRTY,)
    assert log.lines_since(second, prefix="ntfs3(") == ()


def test_lines_since_refuses_a_foreign_mark():
    with pytest.raises(TypeError):
        FakeKernelLog().lines_since("end", prefix="ntfs3(")


def test_fake_kmsg_fixture_is_empty(fake_kmsg):
    assert fake_kmsg.lines_since(fake_kmsg.mark(), prefix="") == ()


def test_fake_kernel_log_has_exactly_the_protocol_methods_plus_queue():
    protocol = {name for name in vars(KernelLog) if not name.startswith("_")}
    fake = {name for name in dir(FakeKernelLog) if not name.startswith("_")}

    assert protocol == {"mark", "lines_since"}
    assert fake == protocol | {"queue"}
