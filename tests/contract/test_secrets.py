"""Secret-leak contract (NFR-09, AC-013, SM-07).

Design Doc: docs/design/steamos-mounter-design.md (sections "Required
Specific Tests > Secret leaks" and "Logging and Secret Handling" rule 5).
ADR-COMMON-0001 decision 4: redaction runs in every handler the logging setup
creates, the stderr fallback included.

A known test key and a recovery-key-shaped value are made live as secrets,
then pushed through every logging output this phase has: the journal datagram,
the sealed memfd, the stderr fallback, the error report each handler prints
on stderr when it fails, and a handler added after setup (caplog). Each way
in is used: the message arguments, an exception raised while the key is live,
and ``SM_*`` fields. Neither value may appear in any output.

The runner half (P2-T03) runs real commands with the logging set up on the
journal and on the stderr fallback: a key on stdin that the command echoes
reaches its DEBUG trace only redacted; a ``secret_stdout`` command's output
and stderr are never offered to logging at all; a key in argv or the
environment is refused before anything is logged.

The BitLocker half (P3-T03) runs every key-bearing call of ``keystore`` and
``bitlocker`` against the fake runner: key input from stdin, ``test_key``,
``store``, ``open_with_secret`` (once with a cryptsetup that echoes the key on
stderr) and ``open_with_file``. The key may be found only in the fake
cryptsetup stdin and in the 0600 key file: never in an argv, the environment,
any other file under the test root, the logs or the terminal.

The reconcile half (P3-T06) runs the stored-key unlock through
``reconcile.run``, once opening and mounting and once rejected: the handler
names the key file to cryptsetup and never opens it, so the key is found
only in that file.

Assertions compare booleans computed beforehand, so a failing test never
prints the bytes. Extended by later phases: ``add``, ``set-key`` and the key
unit.
"""

import builtins
import errno
import io
import logging
import os
import socket
from collections.abc import Iterator

import pytest

from steamos_mounter import bitlocker, keystore, reconcile
from steamos_mounter.bitlocker import UnlockOutcome
from steamos_mounter.errors import SecretHandlingError, UsageError
from steamos_mounter.journal import NOTICE, fields
from steamos_mounter.keystore import KeyStatus
from steamos_mounter.model import InstanceKind, Trigger, VolumeState
from steamos_mounter.runner import Command, CommandResult, SubprocessRunner
from steamos_mounter.sensitive import SecretBytes
from tests.helpers.builders import MEDIABOX, PERSONAL, registry_text
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import (
    LSBLK_ARGV,
    MOUNT,
    PROBE,
    SYSTEMCTL,
    TABLE_ARGV,
    lock_sdb1,
    make_mount_base,
    make_var_run,
    readback_argv,
    runtime_dirs,
    script_desktop_session,
    script_lsblk,
    write_key_file,
    write_registry,
)

TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"
# BitLocker recovery-key shape: eight groups of six digits.
RECOVERY_KEY = b"123456-234567-345678-456789-567890-678901-789012-890123"
SECRETS = (TEST_KEY, RECOVERY_KEY)
REDACTED = b"[REDACTED]"
# Per secret: message argument, three SM_* values, exception text.
REDACTIONS_PER_SECRET = 5
CAT = "/bin/cat"
SH = "/bin/sh"
COMMAND_TIMEOUT = 5.0

log = logging.getLogger("steamos_mounter.tests.secrets")


@pytest.fixture
def live_keys() -> Iterator[tuple[SecretBytes, ...]]:
    secrets = (SecretBytes(TEST_KEY), SecretBytes(RECOVERY_KEY, label="recovery"))
    yield secrets
    for secret in secrets:
        secret.clear()


def log_every_way_in() -> None:
    """Six entries per run: below the default datagram queue length of ten."""
    for value in SECRETS:
        text = value.decode()
        log.info("unlock with %s", text)
        log.log(
            NOTICE,
            "outcome",
            extra=fields(volume=text, reason=f"tool said {text}", step=text),
        )
        try:
            raise RuntimeError(f"cryptsetup echoed {text}")
        except RuntimeError:
            log.exception("unlock failed")


def leaked(output: bytes) -> bool:
    return any(secret in output for secret in SECRETS)


def force_send_error(monkeypatch: pytest.MonkeyPatch, error_number: int) -> None:
    def send(self, data, flags=0):
        raise OSError(error_number, "forced by the test")

    monkeypatch.setattr(socket.socket, "send", send)


@pytest.mark.parametrize("path", ["datagram", "memfd"])
def test_no_secret_reaches_the_journal(
    logging_setup, journal_receiver, monkeypatch, live_keys, path
):
    logging_setup("handler", journal_socket=str(journal_receiver.path))
    if path == "memfd":
        force_send_error(monkeypatch, errno.EMSGSIZE)

    log_every_way_in()

    entries = journal_receiver.drain()
    output = b"".join(entry.payload for entry in entries)
    found = leaked(output)
    assert not found
    assert len(entries) == 6
    assert {entry.via_memfd for entry in entries} == {path == "memfd"}
    assert output.count(REDACTED) == REDACTIONS_PER_SECRET * len(SECRETS)


def test_no_secret_reaches_the_stderr_fallback(logging_setup, tmp_path, live_keys):
    stream = io.StringIO()
    logging_setup("cli", journal_socket=str(tmp_path / "missing"), stderr=stream)

    log_every_way_in()

    output = stream.getvalue().encode()
    found = leaked(output)
    assert not found
    assert output.count(REDACTED) == REDACTIONS_PER_SECRET * len(SECRETS)


def test_no_secret_reaches_the_logging_error_report(
    logging_setup, journal_receiver, monkeypatch, capsys, live_keys
):
    logging_setup("handler", journal_socket=str(journal_receiver.path))
    force_send_error(monkeypatch, errno.ECONNREFUSED)

    log_every_way_in()

    output = capsys.readouterr().err.encode()
    found = leaked(output)
    assert not found
    assert output.count(b"--- Logging error ---") == 6
    # The report holds the message and the caller's exception, not SM_* values.
    assert output.count(REDACTED) == 2 * len(SECRETS)
    assert journal_receiver.drain() == []


def test_no_secret_reaches_the_stderr_fallbacks_error_report(
    logging_setup, tmp_path, capsys, live_keys
):
    stream = io.StringIO()
    logging_setup("cli", journal_socket=str(tmp_path / "missing"), stderr=stream)
    stream.close()

    log_every_way_in()

    output = capsys.readouterr().err.encode()
    found = leaked(output)
    assert not found
    assert output.count(b"--- Logging error ---") == 6
    # The report holds the message and the caller's exception, not SM_* values.
    assert output.count(REDACTED) == 2 * len(SECRETS)


def test_no_secret_reaches_a_handler_added_after_setup(
    logging_setup, journal_receiver, caplog, live_keys
):
    """ADR-COMMON-0001 decision 4: "any handler added later" gets redacted records.

    pytest's caplog handler is added to the root logger after
    ``setup_logging``, behind the redacting handler, as any later handler is.
    """
    logging_setup("handler", journal_socket=str(journal_receiver.path))
    logging.getLogger().addHandler(caplog.handler)

    log_every_way_in()

    records = caplog.records
    held = "\n".join(
        f"{record.msg}|{record.args}|{record.exc_info}|{record.exc_text}|"
        f"{getattr(record, 'sm_fields', None)}"
        for record in records
    ).encode()
    text = caplog.text.encode()
    found = leaked(held) or leaked(text)
    assert not found
    assert len(records) == 6
    assert len(journal_receiver.drain()) == 6
    assert held.count(REDACTED) == REDACTIONS_PER_SECRET * len(SECRETS)
    # caplog's format shows the message and the traceback, not SM_* values.
    assert text.count(REDACTED) == 2 * len(SECRETS)


# --- runner (P2-T03) ---------------------------------------------------------------


@pytest.fixture(params=["journal", "stderr"])
def runner_logs(request, logging_setup, journal_receiver, tmp_path):
    """Redacting logging on one output; returns a function reading that output."""
    if request.param == "journal":
        logging_setup("handler", journal_socket=str(journal_receiver.path))
        return lambda: b"".join(entry.payload for entry in journal_receiver.drain())
    stream = io.StringIO()
    logging_setup("cli", journal_socket=str(tmp_path / "missing"), stderr=stream)
    return lambda: stream.getvalue().encode()


def run(*argv: str, **options: object) -> CommandResult:
    return SubprocessRunner().run(
        Command(argv=argv, timeout=COMMAND_TIMEOUT, **options)
    )


def test_runner_trace_never_holds_a_key_given_on_stdin(runner_logs, live_keys):
    key, recovery = live_keys

    key_result = run(CAT, stdin=key)
    recovery_result = run(CAT, stdin=recovery)

    output = runner_logs()
    echoed = key_result.stdout == TEST_KEY and recovery_result.stdout == RECOVERY_KEY
    found = leaked(output)
    assert echoed
    assert not found
    # Each echoed stdout reaches the trace once, redacted.
    assert output.count(REDACTED) == len(SECRETS)


def test_runner_never_offers_secret_stdout_or_its_stderr_to_logging(runner_logs):
    script = 'read -r key; printf %s "$key"; printf %s "$key" >&2'

    result = run(SH, "-c", script, stdin=TEST_KEY + b"\n", secret_stdout=True)
    try:
        wrapped = result.secret.reveal() == TEST_KEY
    finally:
        result.secret.clear()

    output = runner_logs()
    found = leaked(output) or REDACTED in output
    assert wrapped
    assert not found
    assert b"27 bytes of secret output" in output


@pytest.mark.parametrize("where", ["argv", "environment"])
def test_runner_refuses_a_key_before_logging_anything(runner_logs, live_keys, where):
    text = TEST_KEY.decode()
    argv = (CAT, text) if where == "argv" else (CAT,)
    env_extra = {"KEY": text} if where == "environment" else {}

    with pytest.raises(SecretHandlingError) as raised:
        run(*argv, env_extra=env_extra)

    found = leaked(str(raised.value).encode())
    assert not found
    assert runner_logs() == b""


# --- bitlocker and keystore (P3-T03) -----------------------------------------------

CRYPTSETUP = "/usr/bin/cryptsetup"
CONTAINER_UUID = "658207d5-5177-4a52-a297-31643c64724d"
CONTAINER = "/dev/sdb1"
KEYS_DIR = "var/lib/steamos-mounter/keys"
STORED_KEY = f"/{KEYS_DIR}/{CONTAINER_UUID}.key"
ALLOWED_OPTIONS = {"--test-passphrase", "--type", "--key-file", "--key-file=-"}


def refuse_prompt(_text: str) -> str:
    raise AssertionError("the prompt is not used in this flow")


def key_from_stdin(value: bytes) -> SecretBytes:
    return keystore.read_key_input(
        source="stdin",
        prompt_text="key: ",
        file_path=None,
        stdin=io.BytesIO(value + b"\n"),
        tty_prompt=refuse_prompt,
    )


def files_holding(root, value: bytes) -> list[str]:
    return sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() and value in path.read_bytes()
    )


@pytest.mark.parametrize("value", SECRETS, ids=["test-key", "recovery-key"])
def test_key_reaches_only_cryptsetup_stdin_and_the_key_file(
    runner_logs, ctx, fake_runner, tmp_path, capsys, value
):
    (tmp_path / KEYS_DIR).mkdir(parents=True, mode=0o700)
    (tmp_path / KEYS_DIR).chmod(0o700)
    echoed = b"cryptsetup: bad key " + value
    fake_runner.on(
        CRYPTSETUP,
        Answer(),  # test_key
        Answer(returncode=1, stderr=echoed),  # open_with_secret, hostile stderr
        Answer(),  # open_with_secret
        Answer(),  # open_with_file
    )

    key = key_from_stdin(value)
    try:
        outcomes = (
            bitlocker.test_key(ctx, CONTAINER, key),
            keystore.store(ctx, CONTAINER_UUID, key),
            bitlocker.open_with_secret(ctx, CONTAINER, CONTAINER_UUID, key),
            bitlocker.open_with_secret(ctx, CONTAINER, CONTAINER_UUID, key),
        )
    finally:
        key.clear()
    stored_status = keystore.status(ctx, CONTAINER_UUID)
    file_outcome = bitlocker.open_with_file(
        ctx, CONTAINER, CONTAINER_UUID, str(keystore.key_path(ctx, CONTAINER_UUID))
    )

    logs = runner_logs()
    terminal = capsys.readouterr()
    calls = fake_runner.calls
    in_logs = value in logs or value.decode() in terminal.out + terminal.err
    in_argv_or_env = any(
        value.decode() in item
        for call in calls
        for item in (*call.argv, *call.env_extra, *call.env_extra.values())
    )
    stdin_holds_key = [call.stdin == value for call in calls]
    holders = files_holding(tmp_path, value)
    options = {item for call in calls for item in call.argv if item.startswith("-")}
    assert outcomes == (
        UnlockOutcome.OPENED,
        None,
        UnlockOutcome.FAILED,
        UnlockOutcome.OPENED,
    )
    assert stored_status is KeyStatus.OK
    assert file_outcome is UnlockOutcome.OPENED
    assert not in_logs
    assert not in_argv_or_env
    assert stdin_holds_key == [True, True, True, False]
    assert [call.secret_stdin for call in calls] == [True, True, True, False]
    assert holders == [f"{KEYS_DIR}/{CONTAINER_UUID}.key"]
    # The stored-key open names the file; no argv item carries a key value.
    assert calls[-1].argv[4:6] == ("--key-file", str(tmp_path) + STORED_KEY)
    assert options == ALLOWED_OPTIONS
    # cryptsetup's hostile stderr reached the log, redacted.
    assert REDACTED in logs


@pytest.mark.parametrize("value", SECRETS, ids=["test-key", "recovery-key"])
def test_refused_key_input_never_carries_the_key(runner_logs, capsys, value):
    with pytest.raises(UsageError) as raised:
        key_from_stdin(value + b"\x00")
    error = raised.value
    try:
        raise RuntimeError("set-key failed") from error
    except RuntimeError:
        log.exception("key input refused: %s (%s)", error, error.detail)

    shown = f"{error}|{error.user_message}|{error.detail}|{error!r}".encode()
    terminal = capsys.readouterr()
    found = (
        value in shown
        or value in runner_logs()
        or value.decode() in terminal.out + terminal.err
    )
    assert not found


# --- reconcile: the stored-key unlock (P3-T06) -------------------------------------

PERSONAL_DEVICE_PATH = f"/dev/disk/by-uuid/{CONTAINER_UUID}"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
TOOL_MAPPING = f"steamos-mounter-{CONTAINER_UUID}"
LOCKED_TREE = Answer.from_fixture("lsblk-tree-personal-locked.json", returncode=0)


@pytest.fixture
def opened_paths(monkeypatch) -> list[str]:
    """Every path ``open``, ``io.open`` or ``os.open`` is asked for, in order.

    Python reads a file only through one of these, so a key file that is
    never among them was never read into Python (``lstat`` is not an open).
    """
    seen: list[str] = []

    def watching(real):
        def opener(file, *args, **kwargs):
            if isinstance(file, str | bytes | os.PathLike):
                seen.append(os.fsdecode(file))
            return real(file, *args, **kwargs)

        return opener

    monkeypatch.setattr(builtins, "open", watching(builtins.open))
    monkeypatch.setattr(io, "open", watching(io.open))
    monkeypatch.setattr(os, "open", watching(os.open))
    return seen


def given_personal_locked_with_a_stored_key(ctx, host_tree, tmp_path, fake_runner):
    """PERSONAL registered and plugged in locked, its key file 0600; the open hook."""
    runtime_dirs(ctx)
    write_registry(tmp_path, registry_text([MEDIABOX, PERSONAL]))
    host_tree.add_sysfs_facts()
    host_tree.link_by_uuid(CONTAINER_UUID, "sdb1")
    make_mount_base(tmp_path)
    make_var_run(tmp_path)
    opened = lock_sdb1(tmp_path, TOOL_MAPPING)
    write_key_file(tmp_path, CONTAINER_UUID, TEST_KEY)
    fake_runner.on(LSBLK_ARGV, LOCKED_TREE)
    script_lsblk(fake_runner, "lsblk-columns-tree.json")
    return opened


@pytest.mark.parametrize("cryptsetup", ["opens", "rejects"])
def test_stored_key_unlock_never_reads_or_shows_the_key(
    logging_setup,
    ctx,
    fake_runner,
    host_tree,
    tmp_path,
    capsys,
    caplog,
    opened_paths,
    cryptsetup,
):
    """AC-013, NFR-09: the handler hands cryptsetup a path and never the bytes.

    A stored-key unlock that opens and mounts, and one that cryptsetup
    rejects (the key unit is started), leave the key only in the key file:
    not in an argv, the environment, a stdin, the logs, the terminal, a
    record or the registry. The handler never opens the key file at all.
    """
    stream = io.StringIO()
    logging_setup("handler", journal_socket=str(tmp_path / "missing"), stderr=stream)
    logging.getLogger().addHandler(caplog.handler)
    opened = given_personal_locked_with_a_stored_key(
        ctx, host_tree, tmp_path, fake_runner
    )
    key_file = str(keystore.key_path(ctx, CONTAINER_UUID))
    if cryptsetup == "opens":
        fake_runner.on(CRYPTSETUP, Answer(), hook=opened)
        fake_runner.on(TABLE_ARGV, "findmnt-real-list.json")
        fake_runner.on(PROBE, Answer())
        fake_runner.on(MOUNT, Answer())
        fake_runner.on(
            readback_argv(PERSONAL_PATH),
            Answer.from_fixture("findmnt-personal-ntfs3-rw.json", returncode=0),
        )
    else:
        fake_runner.on(CRYPTSETUP, Answer(returncode=2))
        script_desktop_session(fake_runner)
        fake_runner.on((SYSTEMCTL, "start", "--no-block"), Answer())
    opened_paths.clear()  # the setup wrote the key file; the pass starts here

    outcome = reconcile.run(
        ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH, Trigger.START
    )

    # By basename: a dir_fd-relative open passes only the file name.
    key_was_opened = any(
        os.path.basename(path) == f"{CONTAINER_UUID}.key" for path in opened_paths
    )
    text = TEST_KEY.decode()
    calls = fake_runner.calls
    in_calls = any(
        text in item
        for call in calls
        for item in (*call.argv, *call.env_extra, *call.env_extra.values())
    ) or any(call.stdin is not None for call in calls)
    terminal = capsys.readouterr()
    in_logs = (
        TEST_KEY in stream.getvalue().encode()
        or TEST_KEY in caplog.text.encode()
        or text in terminal.out + terminal.err
    )
    holders = files_holding(tmp_path, TEST_KEY)
    expected = {
        "opens": VolumeState.MOUNTED_RW,
        "rejects": VolumeState.NEEDS_KEY,
    }[cryptsetup]
    key_unit_starts = {"opens": 0, "rejects": 1}[cryptsetup]
    starts = [
        call.argv
        for call in calls
        if call.argv[:3] == (SYSTEMCTL, "start", "--no-block")
    ]
    assert outcome.state is expected
    assert len(starts) == key_unit_starts  # "rejects" reached the key unit start
    assert all(argv[-1].startswith("steamos-mounter-key@") for argv in starts)
    assert not key_was_opened
    assert not in_calls
    assert not in_logs
    assert holders == [f"{KEYS_DIR}/{CONTAINER_UUID}.key"]
    [open_call] = [call.argv for call in calls if call.argv[0] == CRYPTSETUP]
    assert open_call[4:6] == ("--key-file", key_file)
    assert stream.getvalue()  # the pass did log, through the redacting handler
