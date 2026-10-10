"""``DevKmsg``: the ``/dev/kmsg`` tap the NTFS chain reads refusal reasons from.

Design Doc DD-13 and IP-09. Reading the real ``/dev/kmsg`` needs root, so a
regular file in ``/dev/kmsg`` record format stands in for it:
``<prio>,<seq>,<usec>,<flags>;<message>`` plus continuation lines that start
with a space. The messages come from the real ``journal-kernel-ntfs3.txt``
capture. Two kernel behaviours a regular file cannot show are injected at
``os.read``: ``EAGAIN`` (nothing more to read) and ``EPIPE`` (records were
overwritten before they were read).

Where the stand-in differs: a regular file ends a read with EOF instead of
``EAGAIN``, and may return several records, or part of one, per read.
"""

import errno
import logging
import os
from pathlib import Path

import pytest

from steamos_mounter import kmsg
from steamos_mounter.kmsg import KMSG_PATH, DevKmsg
from tests.helpers.fake_kmsg import kernel_messages

SDB5 = "ntfs3(sdb5):"
DM0 = "ntfs3(dm-0):"
DIRTY = 'volume is dirty and "force" flag is not set!'
CHKDSK = "It is recommended to use chkdsk."
OTHER = "usb 1-1: new high-speed USB device number 7 using xhci_hcd"


def record(message: str, seq: int = 1, *, dictionary: bool = False) -> bytes:
    """One ``/dev/kmsg`` record; ``dictionary`` adds continuation lines."""
    text = f"4,{seq},{seq * 1000},-;{message}\n"
    if dictionary:
        text += " SUBSYSTEM=block\n DEVICE=b8:21\n"
    return text.encode()


def append(path: Path, *chunks: bytes) -> None:
    with path.open("ab") as stream:
        for chunk in chunks:
            stream.write(chunk)


def scripted_read(replies: list[bytes | OSError]):
    """An ``os.read`` that answers from ``replies``, in order."""

    def read(_fd: int, _size: int) -> bytes:
        reply = replies.pop(0)
        if isinstance(reply, OSError):
            raise reply
        return reply

    return read


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    """A stand-in log that already holds the capture's older ``sdb5`` lines."""
    path = tmp_path / "kmsg"
    path.write_bytes(
        b"".join(
            record(message, seq) for seq, message in enumerate(kernel_messages("sdb5"))
        )
    )
    return path


def test_default_path_is_dev_kmsg():
    assert KMSG_PATH == "/dev/kmsg"


def test_construction_opens_nothing(tmp_path, caplog):
    """``build_context`` builds a ``DevKmsg`` for non-root commands too."""
    with caplog.at_level(logging.DEBUG, logger="steamos_mounter.kmsg"):
        DevKmsg(path=str(tmp_path / "missing"))

    assert caplog.records == []


def test_lines_since_returns_only_lines_printed_after_the_mark(log_file):
    tap = DevKmsg(path=str(log_file))
    mark = tap.mark()
    append(log_file, record(f"{SDB5} {CHKDSK}", 100), record(f"{SDB5} {DIRTY}", 101))

    assert tap.lines_since(mark, prefix=SDB5) == (
        f"{SDB5} {CHKDSK}",
        f"{SDB5} {DIRTY}",
    )


def test_lines_since_filters_by_the_device_prefix(log_file):
    tap = DevKmsg(path=str(log_file))
    mark = tap.mark()
    append(
        log_file,
        record(f"{DM0} {DIRTY}", 100),
        record(OTHER, 101),
        record(f"{SDB5} {DIRTY}", 102),
    )

    assert tap.lines_since(mark, prefix=SDB5) == (f"{SDB5} {DIRTY}",)
    assert tap.lines_since(mark, prefix=DM0) == (f"{DM0} {DIRTY}",)


def test_mark_with_nothing_new_gives_no_lines(log_file):
    tap = DevKmsg(path=str(log_file))

    mark = tap.mark()

    assert tap.lines_since(mark, prefix=SDB5) == ()


def test_continuation_lines_are_not_messages(log_file):
    tap = DevKmsg(path=str(log_file))
    mark = tap.mark()
    append(log_file, record(f"{SDB5} {DIRTY}", 100, dictionary=True))

    assert tap.lines_since(mark, prefix="") == (f"{SDB5} {DIRTY}",)


def test_a_line_without_a_header_is_skipped(log_file):
    tap = DevKmsg(path=str(log_file))
    mark = tap.mark()
    append(log_file, b"no header here\n", b"\n", record(f"{SDB5} {DIRTY}", 100))

    assert tap.lines_since(mark, prefix="") == (f"{SDB5} {DIRTY}",)


def test_lines_since_can_be_asked_again(log_file):
    tap = DevKmsg(path=str(log_file))
    mark = tap.mark()
    append(log_file, record(f"{SDB5} {DIRTY}", 100))

    first = tap.lines_since(mark, prefix=SDB5)
    second = tap.lines_since(mark, prefix=SDB5)

    assert first == second == (f"{SDB5} {DIRTY}",)


def test_a_later_mark_starts_after_the_earlier_steps_lines(log_file):
    """One mark per chain step: step 2 must not see step 1's refusal."""
    tap = DevKmsg(path=str(log_file))
    first = tap.mark()
    append(log_file, record(f"{SDB5} {DIRTY}", 100))
    second = tap.mark()
    append(log_file, record(f"{SDB5} {CHKDSK}", 101))

    assert tap.lines_since(second, prefix=SDB5) == (f"{SDB5} {CHKDSK}",)
    assert tap.lines_since(first, prefix=SDB5) == (
        f"{SDB5} {DIRTY}",
        f"{SDB5} {CHKDSK}",
    )


def test_a_record_split_across_reads_is_joined(log_file):
    tap = DevKmsg(path=str(log_file))
    mark = tap.mark()
    whole = record(f"{SDB5} {DIRTY}", 100)
    append(log_file, whole[:12])

    assert tap.lines_since(mark, prefix=SDB5) == ()

    append(log_file, whole[12:])

    assert tap.lines_since(mark, prefix=SDB5) == (f"{SDB5} {DIRTY}",)


def test_an_undecodable_byte_survives(log_file):
    tap = DevKmsg(path=str(log_file))
    mark = tap.mark()
    append(log_file, b"4,100,1,-;" + SDB5.encode() + b" label \xff\n")

    (line,) = tap.lines_since(mark, prefix=SDB5)

    assert line.encode("utf-8", "surrogateescape") == SDB5.encode() + b" label \xff"


def test_open_is_read_only_and_non_blocking(log_file, monkeypatch):
    seen: list[tuple[str, int]] = []
    real_open = os.open

    def spy(path, flags, *args):
        seen.append((path, flags))
        return real_open(path, flags, *args)

    monkeypatch.setattr(kmsg.os, "open", spy)
    tap = DevKmsg(path=str(log_file))

    tap.mark()
    tap.mark()

    assert seen == [(str(log_file), os.O_RDONLY | os.O_NONBLOCK)]


def test_eagain_ends_the_read(log_file, monkeypatch):
    """The real device answers ``EAGAIN`` once every record has been read."""
    tap = DevKmsg(path=str(log_file))
    mark = tap.mark()
    replies = [record(f"{SDB5} {DIRTY}", 100), BlockingIOError(errno.EAGAIN, "again")]
    monkeypatch.setattr(kmsg.os, "read", scripted_read(replies))

    assert tap.lines_since(mark, prefix=SDB5) == (f"{SDB5} {DIRTY}",)
    assert replies == []


def test_epipe_skips_the_lost_records_and_reads_on(log_file, monkeypatch, caplog):
    tap = DevKmsg(path=str(log_file))
    mark = tap.mark()
    replies = [
        BrokenPipeError(errno.EPIPE, "overwritten"),
        record(f"{SDB5} {DIRTY}", 100),
        BlockingIOError(errno.EAGAIN, "again"),
    ]
    monkeypatch.setattr(kmsg.os, "read", scripted_read(replies))

    with caplog.at_level(logging.DEBUG, logger="steamos_mounter.kmsg"):
        lines = tap.lines_since(mark, prefix=SDB5)

    assert lines == (f"{SDB5} {DIRTY}",)
    assert "overwritten before they were read" in caplog.text


def test_unopenable_log_gives_no_lines_and_one_warning(tmp_path, caplog):
    """IP-09: an unreadable kernel log only makes the reason fall back."""
    tap = DevKmsg(path=str(tmp_path / "missing"))

    with caplog.at_level(logging.WARNING, logger="steamos_mounter.kmsg"):
        first = tap.mark()
        second = tap.mark()
        lines = tap.lines_since(first, prefix=SDB5)

    assert lines == ()
    assert tap.lines_since(second, prefix=SDB5) == ()
    assert len(caplog.records) == 1
    assert "cannot read the kernel log" in caplog.text


def test_a_read_error_stops_the_tap_with_a_warning(log_file, monkeypatch, caplog):
    tap = DevKmsg(path=str(log_file))
    mark = tap.mark()

    def failing_read(fd, size):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(kmsg.os, "read", failing_read)

    with caplog.at_level(logging.WARNING, logger="steamos_mounter.kmsg"):
        lines = tap.lines_since(mark, prefix=SDB5)
        later = tap.mark()

    assert lines == ()
    assert tap.lines_since(later, prefix=SDB5) == ()
    assert len(caplog.records) == 1
    assert "Input/output error" in caplog.text


def test_lines_read_before_a_failure_are_kept(log_file, monkeypatch):
    tap = DevKmsg(path=str(log_file))
    mark = tap.mark()
    replies = [record(f"{SDB5} {DIRTY}", 100), OSError(errno.EIO, "I/O error")]
    monkeypatch.setattr(kmsg.os, "read", scripted_read(replies))

    assert tap.lines_since(mark, prefix=SDB5) == (f"{SDB5} {DIRTY}",)


def test_lines_since_refuses_a_foreign_mark(log_file):
    tap = DevKmsg(path=str(log_file))

    with pytest.raises(TypeError, match="DevKmsg mark"):
        tap.lines_since(0, prefix=SDB5)


def test_a_log_that_cannot_seek_gives_no_lines_and_one_warning(tmp_path, caplog):
    """A FIFO opens like the device but ``lseek`` fails with ``ESPIPE``."""
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    tap = DevKmsg(path=str(fifo))

    with caplog.at_level(logging.WARNING, logger="steamos_mounter.kmsg"):
        mark = tap.mark()
        lines = tap.lines_since(mark, prefix=SDB5)

    assert lines == ()
    assert len(caplog.records) == 1
    assert "Illegal seek" in caplog.text
