"""Secret-leak contract for the CLI key paths: ``add`` of a BitLocker volume.

Design Doc "Required Specific Tests > Secret leaks", "Key Store" and
"Logging and Secret Handling"; PRD AC-012, AC-013, AC-050; ADR-0004 D4,
ADR-COMMON-0001 decision 4. Kept apart from ``test_secrets.py`` so the CLI
half has its own module; it uses the same two values.

``cli.main`` runs ``add`` end to end with the logging set up on the journal
and on the stderr fallback, and a handler added after setup (redacted). The
key comes from the hidden prompt, ``--key-file`` and ``--key-stdin``; it is
accepted, rejected, or cryptsetup crashes while the key is live. The key may
be found only in the fake cryptsetup stdin and, when accepted, in the 0600
key file (plus the owner's own ``--key-file`` input): never in an argv, the
environment, the logs, the terminal, a record, the registry, or a secret
still live after the run. Assertions compare booleans computed beforehand,
so a failing test never prints the bytes.
"""

import io
import logging
import sys
import traceback

import pytest

from steamos_mounter import keystore
from steamos_mounter.errors import ExitCode, UsageError
from steamos_mounter.sensitive import live_secrets
from tests.helpers.cli_env import (
    DAEMON_RELOAD,
    PERSONAL_KEY,
    PERSONAL_UNIT,
    given_host,
    run_cli,
    script_table,
    script_tree,
    script_unit,
)
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import CRYPTSETUP, make_keys_dir

TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"
# BitLocker recovery-key shape: eight groups of six digits.
RECOVERY_KEY = b"123456-234567-345678-456789-567890-678901-789012-890123"
SECRETS = (TEST_KEY, RECOVERY_KEY)
SOURCES = ("prompt", "file", "stdin")
INPUT_FILE = "home/deck/personal.key"


@pytest.fixture(params=["journal", "stderr"])
def cli_logs(request, logging_setup, journal_receiver, tmp_path, caplog):
    """Redacting logging on one output, and caplog's handler after it."""
    if request.param == "journal":
        logging_setup("cli", journal_socket=str(journal_receiver.path))
        read = lambda: b"".join(entry.payload for entry in journal_receiver.drain())  # noqa: E731
    else:
        stream = io.StringIO()
        logging_setup("cli", journal_socket=str(tmp_path / "missing"), stderr=stream)
        read = lambda: stream.getvalue().encode()  # noqa: E731
    logging.getLogger().addHandler(caplog.handler)
    caplog.set_level(logging.DEBUG)
    return read


def given_personal(ctx, tmp_path, fake_runner, test_answer: Answer, hook=None):
    given_host(ctx, tmp_path)
    make_keys_dir(tmp_path)
    script_tree(fake_runner)
    script_table(fake_runner)
    fake_runner.on(CRYPTSETUP, test_answer, hook=hook)
    fake_runner.on(DAEMON_RELOAD, Answer())
    script_unit(fake_runner, PERSONAL_UNIT, "active")


def key_argv(source: str, value: bytes, tmp_path, monkeypatch) -> tuple[str, ...]:
    """Feed ``value`` through ``source``; the matching ``add`` options."""
    if source == "prompt":
        monkeypatch.setattr("getpass.getpass", lambda _text: value.decode())
        return ()
    if source == "file":
        path = tmp_path / INPUT_FILE
        path.parent.mkdir(parents=True)
        path.write_bytes(value + b"\n")
        path.chmod(0o600)
        return ("--key-file", str(path))
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(value + b"\n")))
    return ("--key-stdin",)


def files_holding(root, value: bytes) -> list[str]:
    return sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink() and value in path.read_bytes()
    )


def found_outside(value, result, fake_runner, logs, caplog, capsys) -> dict[str, bool]:
    text = value.decode()
    terminal = capsys.readouterr()
    shown = result.out + result.err + terminal.out + terminal.err
    return {
        "argv_or_env": any(
            text in item
            for call in fake_runner.calls
            for item in (*call.argv, *call.env_extra, *call.env_extra.values())
        ),
        "logs": value in logs or text in caplog.text,
        "terminal": text in shown,
        "live": value in live_secrets(),
    }


CLEAN = {"argv_or_env": False, "logs": False, "terminal": False, "live": False}


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("value", SECRETS, ids=["test-key", "recovery-key"])
def test_an_accepted_key_reaches_only_cryptsetup_stdin_and_the_key_file(
    cli_logs, ctx, tmp_path, fake_runner, monkeypatch, caplog, capsys, source, value
):
    given_personal(ctx, tmp_path, fake_runner, Answer())
    argv = key_argv(source, value, tmp_path, monkeypatch)

    result = run_cli(ctx, "add", "--device", "/dev/sdb1", "--name", "PERSONAL", *argv)

    found = found_outside(value, result, fake_runner, cli_logs(), caplog, capsys)
    [tested] = [call for call in fake_runner.calls if call.argv[0] == CRYPTSETUP]
    stdin_was_key = tested.stdin == value
    expected_files = sorted([PERSONAL_KEY, *([INPUT_FILE] if source == "file" else [])])
    holders = files_holding(tmp_path, value)
    assert result.code == ExitCode.OK
    assert found == CLEAN
    assert stdin_was_key
    assert tested.secret_stdin
    assert holders == expected_files


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("value", SECRETS, ids=["test-key", "recovery-key"])
def test_a_rejected_key_is_stored_nowhere(
    cli_logs, ctx, tmp_path, fake_runner, monkeypatch, caplog, capsys, source, value
):
    echoed = b"cryptsetup: no key available with this passphrase: " + value
    given_personal(ctx, tmp_path, fake_runner, Answer(returncode=2, stderr=echoed))
    argv = key_argv(source, value, tmp_path, monkeypatch)

    result = run_cli(ctx, "add", "--device", "/dev/sdb1", *argv)

    found = found_outside(value, result, fake_runner, cli_logs(), caplog, capsys)
    holders = files_holding(tmp_path, value)
    assert result.code == ExitCode.REFUSED
    assert found == CLEAN
    assert holders == ([INPUT_FILE] if source == "file" else [])


@pytest.mark.parametrize("value", SECRETS, ids=["test-key", "recovery-key"])
def test_a_crash_while_the_key_is_live_never_carries_it(
    cli_logs, ctx, tmp_path, fake_runner, monkeypatch, caplog, capsys, value
):
    def crashed(_command) -> None:
        raise RuntimeError("cryptsetup crashed")

    given_personal(ctx, tmp_path, fake_runner, Answer(), hook=crashed)
    argv = key_argv("stdin", value, tmp_path, monkeypatch)

    result = run_cli(ctx, "add", "--device", "/dev/sdb1", *argv)

    logs = cli_logs()
    found = found_outside(value, result, fake_runner, logs, caplog, capsys)
    holders = files_holding(tmp_path, value)
    assert result.code == ExitCode.FAILED
    assert found == CLEAN
    assert b"cryptsetup crashed" in logs  # the traceback was logged, key-free
    assert holders == []


# --- a key typed where the --key-file path goes ---------------------------------------

UNREADABLE = ("missing", "directory")


def unreadable_key_file(tmp_path, monkeypatch, value: bytes, kind: str) -> str:
    """``value`` as a relative ``--key-file`` that cannot be read as a file."""
    monkeypatch.chdir(tmp_path)
    if kind == "directory":
        (tmp_path / value.decode()).mkdir()
    return value.decode()


@pytest.mark.parametrize("kind", UNREADABLE)
@pytest.mark.parametrize("value", SECRETS, ids=["test-key", "recovery-key"])
def test_a_key_given_as_the_key_file_path_is_never_shown_or_logged(
    cli_logs, ctx, tmp_path, fake_runner, monkeypatch, caplog, capsys, kind, value
):
    given_personal(ctx, tmp_path, fake_runner, Answer())
    path = unreadable_key_file(tmp_path, monkeypatch, value, kind)

    result = run_cli(ctx, "add", "--device", "/dev/sdb1", "--key-file", path)

    found = found_outside(value, result, fake_runner, cli_logs(), caplog, capsys)
    assert result.code == ExitCode.USAGE
    assert found == CLEAN
    assert CRYPTSETUP not in [argv[0] for argv in fake_runner.argvs]


@pytest.mark.parametrize("kind", UNREADABLE)
@pytest.mark.parametrize("value", SECRETS, ids=["test-key", "recovery-key"])
def test_the_key_file_read_error_never_carries_its_path(
    tmp_path, monkeypatch, kind, value
):
    path = unreadable_key_file(tmp_path, monkeypatch, value, kind)

    with pytest.raises(UsageError) as raised:
        keystore.read_key_input(
            source="file",
            prompt_text="",
            file_path=path,
            stdin=io.BytesIO(),
            tty_prompt=pytest.fail,
        )

    error = raised.value
    text = "".join(traceback.format_exception(error)) + error.detail + repr(error)
    carried = value.decode() in text
    generic_detail = error.detail.startswith("the key file could not be read: ")
    assert not carried
    assert generic_detail
    assert error.user_message == keystore.UNREADABLE_FILE
