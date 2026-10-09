"""Unit tests for steamos_mounter.journal over a real datagram socket.

Design Doc: docs/design/steamos-mounter-design.md (sections "Module
Responsibilities and Public Interfaces > journal", "Logging and Secret
Handling" rules 1 to 5, "Integration Point Map" IP-12, and "Required Specific
Tests > Handler enumeration"). ADR-COMMON-0001 decisions 1, 2 and 4.

Entries go through the real kernel to a socket bound in ``tmp_path`` and are
decoded by ``tests.helpers.journal_socket``, written from the native protocol
rather than from the package. Assertions that involve a secret compare
booleans computed beforehand, so a failing test never prints the bytes.
"""

import errno
import inspect
import io
import logging
import os
import socket
from collections.abc import Iterator

import pytest

from steamos_mounter.journal import (
    FIELD_PREFIX,
    JOURNAL_SOCKET,
    NOTICE,
    JournalHandler,
    RedactingFilter,
    fields,
)
from steamos_mounter.sensitive import SecretBytes
from tests.helpers import journal_socket
from tests.helpers.journal_socket import (
    ALL_SEALS,
    MAX_FDS,
    JournalReceiver,
    decode_entry,
)

TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"
KEY_TEXT = TEST_KEY.decode()
REDACTED = "[REDACTED]"
LOGGER_NAME = "steamos_mounter.tests.journal"

log = logging.getLogger(LOGGER_NAME)


@pytest.fixture
def live_key() -> Iterator[SecretBytes]:
    secret = SecretBytes(TEST_KEY)
    yield secret
    secret.clear()


@pytest.fixture
def journal(logging_setup, journal_receiver):
    """Logging set up for the ``handler`` component against the test socket."""
    logging_setup("handler", journal_socket=str(journal_receiver.path))
    return journal_receiver


def raise_send(error_number: int):
    def send(self, data, flags=0):
        raise OSError(error_number, "forced by the test")

    return send


def test_public_constants_match_the_design_doc():
    assert NOTICE == 25
    assert logging.getLevelName(NOTICE) == "NOTICE"
    assert FIELD_PREFIX == "SM_"
    assert JOURNAL_SOCKET == "/run/systemd/journal/socket"


def test_identity_and_fields(journal):
    """AC-041: one identifier, the fixed field names, values as logged."""
    extra = fields(
        volume="MEDIABOX",
        uuid="01DA2B3C4D5E6F70",
        device="/dev/sda1",
        event="reconcile",
        state="MountedRW",
        reason="clean",
        unit="steamos-mounter@sda1.service",
        step="ntfs3:rw",
    )

    line = inspect.currentframe().f_lineno + 1
    log.log(NOTICE, "mounted %s", "/run/media/deck/MEDIABOX", extra=extra)

    entry = journal.one()

    assert not entry.via_memfd
    assert entry.fields == {
        "MESSAGE": "mounted /run/media/deck/MEDIABOX",
        "PRIORITY": "5",
        "SYSLOG_IDENTIFIER": "steamos-mounter",
        "CODE_FILE": __file__,
        "CODE_LINE": str(line),
        "CODE_FUNC": "test_identity_and_fields",
        "SM_COMPONENT": "handler",
        "SM_VOLUME": "MEDIABOX",
        "SM_UUID": "01DA2B3C4D5E6F70",
        "SM_DEVICE": "/dev/sda1",
        "SM_EVENT": "reconcile",
        "SM_STATE": "MountedRW",
        "SM_REASON": "clean",
        "SM_UNIT": "steamos-mounter@sda1.service",
        "SM_STEP": "ntfs3:rw",
    }


def test_fields_keeps_only_given_values_under_the_prefix():
    assert fields() == {"sm_fields": {}}
    assert fields(volume="PERSONAL", step="ntfs3:ro") == {
        "sm_fields": {"SM_VOLUME": "PERSONAL", "SM_STEP": "ntfs3:ro"}
    }


@pytest.mark.parametrize(
    ("level", "priority"),
    [
        (logging.DEBUG, "7"),
        (15, "7"),
        (logging.INFO, "6"),
        (NOTICE - 1, "6"),
        (NOTICE, "5"),
        (logging.WARNING, "4"),
        (logging.ERROR, "3"),
        (logging.CRITICAL, "2"),
        (60, "2"),
    ],
)
def test_priority_follows_the_level(journal, level, priority):
    log.log(level, "progress")

    assert journal.one().fields["PRIORITY"] == priority


def test_multi_line_value_is_length_prefixed(journal):
    log.info("line one\nline two")

    entry = journal.one()

    assert b"MESSAGE\n\x11\x00\x00\x00\x00\x00\x00\x00line one\nline two\n" in (
        entry.payload
    )
    assert b"PRIORITY=6\n" in entry.payload
    assert entry.fields["MESSAGE"] == "line one\nline two"


def test_undecodable_text_is_sent_as_valid_utf8(journal):
    log.info("label %s", "caf\udce9")

    assert journal.one().fields["MESSAGE"] == "label caf\\udce9"


def test_traceback_is_in_the_message_and_redacted(journal, live_key):
    try:
        raise RuntimeError(f"cryptsetup printed {KEY_TEXT}")
    except RuntimeError:
        log.exception("unlock failed for %s", "PERSONAL")

    message = journal.one().fields["MESSAGE"]
    leaked = KEY_TEXT in message
    lines = message.splitlines()

    assert not leaked
    assert lines[0] == "unlock failed for PERSONAL"
    assert lines[1] == "Traceback (most recent call last):"
    assert lines[-1] == f"RuntimeError: cryptsetup printed {REDACTED}"


def test_sm_values_are_redacted_and_the_callers_dict_is_kept(journal, live_key):
    extra = fields(volume="PERSONAL", reason=f"tool said {KEY_TEXT}")

    log.warning("needs a key", extra=extra)

    entry = journal.one()
    leaked = TEST_KEY in entry.payload
    redacted = entry.fields["SM_REASON"] == f"tool said {REDACTED}"
    caller_kept = extra["sm_fields"]["SM_REASON"] == f"tool said {KEY_TEXT}"

    assert not leaked
    assert redacted
    assert caller_kept
    assert entry.fields["SM_VOLUME"] == "PERSONAL"


def test_emsgsize_sends_the_same_entry_in_a_sealed_memfd(journal, monkeypatch):
    monkeypatch.setattr(socket.socket, "send", raise_send(errno.EMSGSIZE))

    log.error("mount failed\nsecond line", extra=fields(volume="MEDIABOX"))

    entry = journal.one()
    assert entry.via_memfd
    assert entry.seals == ALL_SEALS
    assert entry.fields["MESSAGE"] == "mount failed\nsecond line"
    assert entry.fields["PRIORITY"] == "3"
    assert entry.fields["SYSLOG_IDENTIFIER"] == "steamos-mounter"
    assert entry.fields["SM_COMPONENT"] == "handler"
    assert entry.fields["SM_VOLUME"] == "MEDIABOX"


def test_other_send_errors_go_to_handle_error_redacted(
    journal, monkeypatch, capsys, live_key
):
    monkeypatch.setattr(socket.socket, "send", raise_send(errno.ECONNREFUSED))

    log.error("unlock with %s", KEY_TEXT)

    err = capsys.readouterr().err
    leaked = KEY_TEXT in err
    assert not leaked
    assert "--- Logging error ---" in err
    assert f"unlock with {REDACTED}" in err
    assert journal.drain() == []


def test_stderr_handler_errors_are_reported_redacted_with_their_chain(
    logging_setup, tmp_path, capsys, live_key
):
    stream = io.StringIO()
    logging_setup("cli", journal_socket=str(tmp_path / "missing"), stderr=stream)
    stream.close()

    try:
        raise RuntimeError(f"cryptsetup printed {KEY_TEXT}")
    except RuntimeError:
        log.exception("unlock failed")

    err = capsys.readouterr().err
    leaked = KEY_TEXT in err
    assert not leaked
    assert err.startswith("--- Logging error ---\nTraceback (most recent call last):")
    assert f"RuntimeError: cryptsetup printed {REDACTED}" in err
    assert "ValueError: I/O operation on closed file" in err
    assert err.endswith("Message: 'unlock failed'\n")


@pytest.mark.parametrize("disabled", ["raise_exceptions", "no_stderr"])
def test_error_report_is_skipped_like_loggings_own(
    journal, monkeypatch, capsys, disabled
):
    with monkeypatch.context() as patch:
        patch.setattr(socket.socket, "send", raise_send(errno.ECONNREFUSED))
        if disabled == "raise_exceptions":
            patch.setattr(logging, "raiseExceptions", False)
        else:
            patch.setattr("sys.stderr", None)

        log.error("mount failed")

    assert capsys.readouterr().err == ""
    assert journal.drain() == []


def test_unformattable_arguments_do_not_raise_and_are_not_logged(journal, live_key):
    log.info("count %d of %s", KEY_TEXT)

    message = journal.one().fields["MESSAGE"]
    leaked = KEY_TEXT in message

    assert not leaked
    assert message == "log message could not be formatted: 'count %d of %s'"


@pytest.mark.parametrize(
    "value",
    [b"pa\\ss", b"bell\x07key", b"lone\xffkey"],
    ids=["backslash", "control", "lone-surrogate"],
)
def test_unformattable_template_is_redacted_before_it_is_escaped(journal, value):
    """repr() escapes these characters; redacting after it would miss the secret."""
    text = value.decode("utf-8", "surrogateescape")
    with SecretBytes(value):
        log.info(f"unlock {text} %d", "not-a-number")

        message = journal.one().fields["MESSAGE"]

    escaped = repr(text)[1:-1]
    leaked = text in message or escaped in message
    assert not leaked
    assert message == "log message could not be formatted: 'unlock [REDACTED] %d'"


def test_more_entries_than_the_kernel_queue_holds_all_arrive_in_order(journal):
    """Docker's net.unix.max_dgram_qlen is 10; the receiver must keep reading."""
    for number in range(50):
        log.info("entry %d", number)

    messages = [entry.fields["MESSAGE"] for entry in journal.drain()]

    assert messages == [f"entry {number}" for number in range(50)]


def test_oversized_entry_goes_through_a_real_sealed_memfd(journal):
    """No patching: 4 MiB is over any default send buffer, so send raises EMSGSIZE."""
    message = "x" * (4 << 20)

    line = inspect.currentframe().f_lineno + 1
    log.info(message, extra=fields(volume="MEDIABOX"))

    entry = journal.one()
    # The datagram encoding of the same entry, written from the protocol.
    expected = b"".join(
        f"{name}={value}\n".encode()
        for name, value in [
            ("MESSAGE", message),
            ("PRIORITY", "6"),
            ("SYSLOG_IDENTIFIER", "steamos-mounter"),
            ("CODE_FILE", __file__),
            ("CODE_LINE", str(line)),
            ("CODE_FUNC", "test_oversized_entry_goes_through_a_real_sealed_memfd"),
            ("SM_COMPONENT", "handler"),
            ("SM_VOLUME", "MEDIABOX"),
        ]
    )
    same_bytes = entry.payload == expected
    assert entry.via_memfd
    assert entry.seals == ALL_SEALS
    assert len(entry.payload) == len(expected)
    assert same_bytes


def test_journal_handler_refuses_a_missing_socket(tmp_path):
    with pytest.raises(OSError):
        JournalHandler("handler", str(tmp_path / "missing"))


@pytest.mark.parametrize("target", ["journal", "stderr"])
def test_every_root_handler_has_the_redacting_filter_first(
    logging_setup, journal_receiver, tmp_path, target
):
    """Required specific test "Handler enumeration"."""
    path = journal_receiver.path if target == "journal" else tmp_path / "missing"

    handlers = logging_setup("cli", journal_socket=str(path), stderr=io.StringIO())

    root = logging.getLogger()
    assert root.handlers == handlers
    assert len(handlers) == 1
    assert all(isinstance(handler.filters[0], RedactingFilter) for handler in handlers)
    assert isinstance(handlers[0], JournalHandler) is (target == "journal")
    assert root.level == logging.DEBUG


def test_stderr_fallback_when_the_socket_is_absent(logging_setup, tmp_path, live_key):
    stream = io.StringIO()
    logging_setup("cli", journal_socket=str(tmp_path / "missing"), stderr=stream)

    log.log(
        NOTICE,
        "mounted %s with %s",
        "MEDIABOX",
        KEY_TEXT,
        extra=fields(volume="MEDIABOX", reason=KEY_TEXT),
    )
    log.debug("trace")

    text = stream.getvalue()
    leaked = KEY_TEXT in text
    assert not leaked
    assert text == (
        f"steamos-mounter[cli] NOTICE: mounted MEDIABOX with {REDACTED}"
        f" SM_REASON={REDACTED} SM_VOLUME=MEDIABOX\n"
        "steamos-mounter[cli] DEBUG: trace\n"
    )


def test_stderr_fallback_puts_the_traceback_after_the_line(logging_setup, tmp_path):
    stream = io.StringIO()
    logging_setup("doctor", journal_socket=str(tmp_path / "missing"), stderr=stream)

    try:
        raise ValueError("bad registry")
    except ValueError:
        log.exception("registry unusable", extra=fields(event="doctor"))

    lines = stream.getvalue().splitlines()
    assert (
        lines[0] == "steamos-mounter[doctor] ERROR: registry unusable SM_EVENT=doctor"
    )
    assert lines[1] == "Traceback (most recent call last):"
    assert lines[-1] == "ValueError: bad registry"


def test_stderr_fallback_defaults_to_sys_stderr(logging_setup, tmp_path, capsys):
    logging_setup("installer", journal_socket=str(tmp_path))

    log.warning("step skipped")

    assert (
        capsys.readouterr().err == "steamos-mounter[installer] WARNING: step skipped\n"
    )


def test_redacting_filter_leaves_only_redacted_text_on_the_record(live_key):
    try:
        raise RuntimeError(f"echoed {KEY_TEXT}")
    except RuntimeError as error:
        exc_info = (type(error), error, error.__traceback__)
    record = logging.LogRecord(
        LOGGER_NAME,
        logging.ERROR,
        __file__,
        1,
        "key %s for %s",
        (KEY_TEXT, "X"),
        exc_info,
        func="unlock",
        sinfo=f"Stack (most recent call last):\n  {KEY_TEXT}",
    )
    record.sm_fields = {"SM_STEP": KEY_TEXT}

    kept = RedactingFilter().filter(record)

    rendered = f"{record.msg}|{record.exc_text}|{record.stack_info}|{record.sm_fields}"
    leaked = KEY_TEXT in rendered
    assert kept is True
    assert not leaked
    assert record.msg == f"key {REDACTED} for X"
    assert record.args is None
    assert record.exc_info is None
    assert record.exc_text.endswith(f"RuntimeError: echoed {REDACTED}")
    assert record.stack_info == f"Stack (most recent call last):\n  {REDACTED}"
    assert record.sm_fields == {"SM_STEP": REDACTED}


def test_redacting_filter_keeps_absent_parts_absent():
    record = logging.LogRecord(
        LOGGER_NAME, logging.INFO, __file__, 1, "plain", None, None
    )

    RedactingFilter().filter(record)

    assert record.msg == "plain"
    assert record.exc_text is None
    assert record.stack_info is None
    assert not hasattr(record, "sm_fields")


def test_decoder_reads_both_encodings_and_rejects_repeats():
    """Self-test of the test decoder, against hand-written protocol bytes."""
    data = b"A=1\nB\n\x03\x00\x00\x00\x00\x00\x00\x00x\nz\nC=\n"

    assert decode_entry(data) == {"A": "1", "B": "x\nz", "C": ""}
    with pytest.raises(ValueError, match="repeated"):
        decode_entry(b"A=1\nA=2\n")
    with pytest.raises(ValueError, match="not terminated"):
        decode_entry(b"B\n\x01\x00\x00\x00\x00\x00\x00\x00xy")
    with pytest.raises(ValueError, match="truncated length"):
        decode_entry(b"B\n\x01\x00")
    with pytest.raises(ValueError, match="terminating newline"):
        decode_entry(b"A=1")
    assert decode_entry(b"A" * 64 + b"=1\n") == {"A" * 64: "1"}


@pytest.mark.parametrize(
    "line",
    [b"a=1\n", b"1A=1\n", b"_A=1\n", b"A-B=1\n", b"=1\n", b"A" * 65 + b"=1\n"],
    ids=["lowercase", "digit-first", "underscore-first", "dash", "empty", "too-long"],
)
def test_decoder_rejects_names_journald_refuses(line):
    with pytest.raises(ValueError, match="invalid field name"):
        decode_entry(line)


def send_raw(path, payload: bytes, fds: list[int] | None = None) -> None:
    """One datagram straight to the receiver, outside the package."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
        # send_fds does not pass its address argument on; connect instead.
        client.connect(str(path))
        if fds:
            socket.send_fds(client, [payload], fds)
        else:
            client.send(payload)


def test_receiver_rejects_truncated_ancillary_data(journal_receiver):
    """Self-test: more descriptors than the receiver takes is an error, not a loss."""
    read_end, write_end = os.pipe()
    try:
        send_raw(journal_receiver.path, b"", [read_end] * (MAX_FDS + 1))
    finally:
        os.close(read_end)
        os.close(write_end)

    with pytest.raises(ValueError, match="ancillary data truncated"):
        journal_receiver.drain()


def test_receiver_raises_any_reader_failure_not_only_value_error(journal_receiver):
    """Self-test: a pipe is not a memfd, so reading its seals fails with OSError."""
    read_end, write_end = os.pipe()
    try:
        send_raw(journal_receiver.path, b"", [read_end])
    finally:
        os.close(read_end)
        os.close(write_end)

    with pytest.raises(OSError) as raised:
        journal_receiver.drain()

    assert raised.value.errno == errno.EINVAL


def test_receiver_consumes_the_tail_after_a_failure(journal_receiver):
    """Self-test: the entry behind a bad one is not left for the next drain."""
    read_end, write_end = os.pipe()
    try:
        send_raw(journal_receiver.path, b"A=1\n", [read_end])
    finally:
        os.close(read_end)
        os.close(write_end)
    send_raw(journal_receiver.path, b"GOOD=1\n")

    with pytest.raises(ValueError, match="one descriptor and an empty payload"):
        journal_receiver.drain()

    assert journal_receiver.drain() == []


def test_receiver_raises_a_failed_read_then_reports_it_stopped(tmp_path, monkeypatch):
    """Self-test: a read error ends the reader, and every drain says so at once."""

    def fail(*args, **kwargs):
        raise OSError(errno.EBADF, "forced by the test")

    monkeypatch.setattr(journal_socket.socket, "recv_fds", fail)
    receiver = JournalReceiver(tmp_path / "r")
    try:
        with pytest.raises(OSError, match="forced by the test"):
            receiver.drain()
        with pytest.raises(AssertionError, match="stopped reading"):
            receiver.drain()
    finally:
        receiver.close()
