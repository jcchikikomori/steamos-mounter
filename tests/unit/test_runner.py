"""Unit tests for steamos_mounter.runner with real processes in the container.

Design Doc: docs/design/steamos-mounter-design.md (sections "runner (the single
subprocess seam)" rules 1 to 6, "Data Contracts > runner.run", DD-01 and
DD-14). ADR-COMMON-0001 decisions 4 and 5.

Real ``/bin/sh``, ``/bin/cat`` and ``/usr/bin/env`` prove the environment, the
timeout, the group kill and the drain. Docker runs the tests without the right
to switch uid or clear supplementary groups, so those options are checked on
a ``Popen`` subclass that records them and runs the command without them.
Assertions that involve a secret compare booleans computed beforehand.
"""

import io
import logging
import os
import signal
import subprocess
import time
from collections.abc import Iterator

import pytest

from steamos_mounter import runner
from steamos_mounter.errors import SecretHandlingError
from steamos_mounter.runner import (
    BASE_ENV,
    Command,
    CommandResult,
    SubprocessRunner,
    check_command,
)
from steamos_mounter.sensitive import SecretBytes

SH = "/bin/sh"
CAT = "/bin/cat"
ENV = "/usr/bin/env"
TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"
TIMEOUT = 5.0
# Upper bound for calls that must not wait for a 30 s child.
QUICK = 3.0
LOGGER = "steamos_mounter.runner"


@pytest.fixture
def live_key() -> Iterator[SecretBytes]:
    secret = SecretBytes(TEST_KEY)
    yield secret
    secret.clear()


@pytest.fixture
def debug_log(caplog):
    """Runner records at DEBUG; only for tests without a live secret."""
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    return caplog


@pytest.fixture
def redacted_log(logging_setup, tmp_path) -> io.StringIO:
    """Redacting stderr-fallback logging into a buffer, for tests with a secret."""
    stream = io.StringIO()
    logging_setup("cli", journal_socket=str(tmp_path / "missing"), stderr=stream)
    return stream


@pytest.fixture
def popen_calls(monkeypatch) -> list[dict[str, object]]:
    """Records Popen's options; runs the command without the uid switch."""
    seen: list[dict[str, object]] = []

    class RecordingPopen(subprocess.Popen):
        def __init__(self, args, **options):
            seen.append(dict(options))
            for name in ("user", "group", "extra_groups"):
                options.pop(name, None)
            super().__init__(args, **options)

    monkeypatch.setattr(runner.subprocess, "Popen", RecordingPopen)
    return seen


@pytest.fixture
def no_popen(monkeypatch) -> list[object]:
    """Fails the run if a process would start; returns what tried."""
    attempts: list[object] = []

    def refuse(args, **options):
        attempts.append(args)
        raise AssertionError("a process was started")

    monkeypatch.setattr(runner.subprocess, "Popen", refuse)
    return attempts


def run(*argv: str, **options: object) -> CommandResult:
    options.setdefault("timeout", TIMEOUT)
    return SubprocessRunner().run(Command(argv=argv, **options))


def env_of(result: CommandResult) -> dict[str, str]:
    return dict(line.split("=", 1) for line in result.text().splitlines())


def gone(pid: int) -> bool:
    """No such process, or only a zombie left (nobody reaps orphans in Docker)."""
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as stat:
            state = stat.read().rpartition(")")[2].split()[0]
    except FileNotFoundError:
        return True
    return state in {"Z", "X"}


# --- rule 3: the fixed environment (DD-01) --------------------------------------


def test_base_env_is_the_dd01_locale_and_path():
    assert dict(BASE_ENV) == {"LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/usr/sbin"}


def test_base_env_cannot_be_changed():
    with pytest.raises(TypeError):
        BASE_ENV["LC_ALL"] = "C"  # type: ignore[index]


def test_environment_is_exactly_the_base_env(monkeypatch):
    monkeypatch.setenv("SM_INHERITED_PROBE", "1")

    result = run(ENV)

    assert result.returncode == 0
    assert env_of(result) == {"LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/usr/sbin"}


def test_environment_adds_only_the_named_extras(monkeypatch):
    monkeypatch.setenv("SM_INHERITED_PROBE", "1")

    result = run(ENV, env_extra={"DISPLAY": ":0", "XAUTHORITY": "/tmp/xauth"})

    assert env_of(result) == {
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/usr/sbin",
        "DISPLAY": ":0",
        "XAUTHORITY": "/tmp/xauth",
    }


def test_output_is_bytes_mode():
    result = run(SH, "-c", "printf 'a\\nb'; printf 'c' >&2")

    assert result == CommandResult(
        argv=(SH, "-c", "printf 'a\\nb'; printf 'c' >&2"),
        returncode=0,
        stdout=b"a\nb",
        stderr=b"c",
        secret=None,
        timed_out=False,
        not_found=False,
        overflow=False,
    )


def test_returncode_of_a_failing_command():
    result = run(SH, "-c", "exit 3")

    assert (result.returncode, result.timed_out, result.not_found) == (3, False, False)


def test_text_decodes_invalid_utf8_with_surrogateescape():
    result = run(SH, "-c", "printf '\\377ok\\303\\211'; printf '\\376err' >&2")

    assert result.stdout == b"\xffok\xc3\x89"
    assert result.text() == "\udcffokÉ"
    assert result.err_text() == "\udcfeerr"
    assert result.text().encode("utf-8", "surrogateescape") == result.stdout


def test_invalid_utf8_output_is_logged_without_error(debug_log):
    run(SH, "-c", "printf '\\377ok'")

    assert any("\udcffok" in record.getMessage() for record in debug_log.records)


# --- rule 1: no secret in argv or the environment ---------------------------------


@pytest.mark.parametrize(
    "form", ["wrapper", "revealed bytes", "revealed text", "text inside an option"]
)
def test_secret_in_argv_is_refused_before_anything_runs_or_logs(
    live_key, redacted_log, no_popen, form
):
    item = {
        "wrapper": live_key,
        "revealed bytes": live_key.reveal(),
        "revealed text": TEST_KEY.decode(),
        "text inside an option": f"--key={TEST_KEY.decode()}",
    }[form]

    with pytest.raises(SecretHandlingError) as raised:
        run("/usr/bin/cryptsetup", "open", item)

    message_leaks = TEST_KEY.decode() in str(raised.value)
    assert not message_leaks
    assert str(raised.value) == "a secret is in argv[2]"
    assert redacted_log.getvalue() == ""
    assert no_popen == []


@pytest.mark.parametrize("form", ["wrapper", "revealed bytes", "revealed text"])
def test_secret_in_the_environment_is_refused(live_key, redacted_log, no_popen, form):
    value = {
        "wrapper": live_key,
        "revealed bytes": live_key.reveal(),
        "revealed text": TEST_KEY.decode(),
    }[form]

    with pytest.raises(SecretHandlingError, match="a secret is in the environment"):
        run(ENV, env_extra={"KEY": value})

    assert redacted_log.getvalue() == ""
    assert no_popen == []


def test_secret_as_an_environment_name_is_refused(live_key, no_popen):
    with pytest.raises(SecretHandlingError):
        run(ENV, env_extra={TEST_KEY.decode(): "1"})


def test_secret_bytes_as_stdin_are_allowed(live_key):
    result = run(CAT, stdin=live_key)

    echoed = result.stdout == TEST_KEY
    assert echoed


def test_cleared_secret_no_longer_blocks_its_text():
    secret = SecretBytes(TEST_KEY)
    secret.clear()

    assert check_command(Command(argv=(SH, TEST_KEY.decode()), timeout=TIMEOUT)) is None


# --- rule 2: absolute argv[0], environment names ---------------------------------


@pytest.mark.parametrize("argv", [(), ("lsblk",), ("./bin/lsblk",), ("",)])
def test_relative_or_missing_argv0_is_refused(argv, no_popen):
    with pytest.raises(ValueError, match="argv\\[0\\] must be an absolute path"):
        SubprocessRunner().run(Command(argv=argv, timeout=TIMEOUT))


@pytest.mark.parametrize("name", ["display", "1X", "A-B", "", "A B", "ÄX"])
def test_bad_environment_name_is_refused(name, no_popen):
    with pytest.raises(ValueError, match="invalid environment variable name"):
        run(ENV, env_extra={name: "1"})


@pytest.mark.parametrize("name", ["DISPLAY", "_X", "XDG_RUNTIME_DIR", "A1"])
def test_good_environment_names_reach_the_child(name):
    result = run(ENV, env_extra={name: "1"})

    assert env_of(result)[name] == "1"


def test_non_text_argv_item_is_refused(no_popen):
    with pytest.raises(TypeError, match="argv items must be str"):
        run(SH, b"-c")


def test_non_text_environment_value_is_refused(no_popen):
    with pytest.raises(TypeError, match="environment names and values must be str"):
        run(ENV, env_extra={"N": 1})


# --- rule 4: Popen options --------------------------------------------------------


def test_popen_gets_a_new_group_closed_fds_and_the_fixed_env(popen_calls):
    run(SH, "-c", "true")

    (options,) = popen_calls
    assert options == {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": {"LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/usr/sbin"},
        "close_fds": True,
        "process_group": 0,
        "user": None,
        "group": None,
    }


def test_uid_switch_passes_user_group_and_clears_extra_groups(popen_calls):
    run(SH, "-c", "true", user=1000, group=1000)

    (options,) = popen_calls
    assert (options["user"], options["group"], options["extra_groups"]) == (
        1000,
        1000,
        [],
    )


def test_stdin_is_a_pipe_only_when_given(popen_calls):
    run(CAT, stdin=b"x")

    assert popen_calls[0]["stdin"] == subprocess.PIPE


def test_secret_stdout_discards_stderr_unread(popen_calls):
    result = run(SH, "-c", "printf out; printf err >&2", secret_stdout=True)

    assert popen_calls[0]["stderr"] == subprocess.DEVNULL
    assert result.stderr == b""
    result.secret.clear()


def test_child_runs_in_its_own_process_group():
    result = run(SH, "-c", "ps_pgid=$(cut -d' ' -f5 /proc/$$/stat); echo $$ $ps_pgid")

    pid, pgid = result.text().split()
    assert pid == pgid
    assert int(pgid) != os.getpgrp()


# --- rule 5: stdin, timeout, drain ------------------------------------------------


def test_stdin_is_written_and_closed():
    result = run(CAT, stdin=b"abc\n")

    assert (result.returncode, result.stdout) == (0, b"abc\n")


def test_empty_stdin_is_closed_at_once():
    result = run(CAT, stdin=b"")

    assert (result.returncode, result.stdout, result.timed_out) == (0, b"", False)


def test_large_stdin_and_stdout_move_together():
    data = bytes(range(256)) * 4096

    result = run(CAT, stdin=data)

    assert result.returncode == 0
    assert result.stdout == data


def test_stdin_the_child_never_reads_is_dropped():
    result = run("/bin/true", stdin=b"x" * (1 << 20))

    assert (result.returncode, result.timed_out) == (0, False)


def test_large_stdout_without_a_cap_is_read_whole():
    result = run(SH, "-c", "head -c 1048576 /dev/zero")

    assert (result.returncode, result.overflow) == (0, False)
    assert len(result.stdout) == 1 << 20


def test_timeout_sets_timed_out_and_kills_the_group():
    started = time.monotonic()

    result = run(SH, "-c", "sleep 30 & echo $!; wait", timeout=0.5)

    elapsed = time.monotonic() - started
    assert (result.timed_out, result.returncode) == (True, None)
    assert elapsed < QUICK
    assert gone(int(result.text()))


def test_timeout_escalates_to_sigkill_when_sigterm_is_ignored(monkeypatch):
    monkeypatch.setattr(runner, "TERM_GRACE", 0.2)
    signals: list[int] = []
    real_killpg = os.killpg

    def killpg(group, signum):
        signals.append(signum)
        real_killpg(group, signum)

    monkeypatch.setattr(runner.os, "killpg", killpg)
    started = time.monotonic()

    result = run(SH, "-c", "trap '' TERM; sleep 30 & echo $!; wait", timeout=0.3)

    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert result.timed_out
    assert time.monotonic() - started < QUICK
    assert gone(int(result.text()))


def test_group_that_survives_sigkill_is_reported(monkeypatch, debug_log):
    monkeypatch.setattr(runner, "TERM_GRACE", 0.1)
    monkeypatch.setattr(runner, "KILL_GRACE", 0.1)
    groups: list[int] = []
    monkeypatch.setattr(runner.os, "killpg", lambda group, signum: groups.append(group))

    try:
        result = run("/bin/sleep", "30", timeout=0.1)
    finally:
        for group in set(groups):
            os.killpg(group, signal.SIGKILL)

    assert result.timed_out
    assert f"process group {groups[0]} still runs after SIGKILL" in debug_log.text


def test_sigkill_to_an_emptied_group_is_harmless(monkeypatch):
    signals: list[int] = []
    real_killpg = os.killpg

    def killpg(group, signum):
        signals.append(signum)
        real_killpg(group, signum)

    monkeypatch.setattr(runner.os, "killpg", killpg)

    # SIGTERM ends the only member, so the group is gone before SIGKILL.
    result = run(SH, "-c", "exec sleep 30", timeout=0.1)

    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert result.timed_out


def test_drain_stops_after_half_a_second_when_a_daemon_keeps_the_pipes(request):
    started = time.monotonic()

    result = run(SH, "-c", "sleep 30 & echo $!")

    elapsed = time.monotonic() - started
    daemon = int(result.text())
    request.addfinalizer(lambda: os.kill(daemon, signal.SIGKILL))
    assert (result.returncode, result.timed_out) == (0, False)
    assert runner.DRAIN_LIMIT <= elapsed < QUICK
    assert not gone(daemon)


def test_output_written_just_before_exit_is_drained():
    result = run(SH, "-c", "head -c 300000 /dev/zero; exit 4")

    assert (result.returncode, len(result.stdout)) == (4, 300000)


def test_exception_while_waiting_stops_the_group(monkeypatch):
    started: list[subprocess.Popen] = []

    class TrackingPopen(subprocess.Popen):
        def __init__(self, args, **options):
            super().__init__(args, **options)
            started.append(self)

    monkeypatch.setattr(runner.subprocess, "Popen", TrackingPopen)

    class WaitInterruptedError(Exception):
        pass

    def interrupt(signum, frame):
        raise WaitInterruptedError

    previous = signal.signal(signal.SIGALRM, interrupt)
    signal.setitimer(signal.ITIMER_REAL, 0.2)
    try:
        with pytest.raises(WaitInterruptedError):
            run("/bin/sleep", "30", timeout=TIMEOUT)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)

    assert started[0].returncode == -signal.SIGTERM


# --- not found, overflow, secret stdout --------------------------------------------


def test_missing_executable_sets_not_found(debug_log):
    result = run("/nonexistent/steamos-mounter-probe", "-x")

    assert result == CommandResult(
        argv=("/nonexistent/steamos-mounter-probe", "-x"),
        returncode=None,
        stdout=b"",
        stderr=b"",
        secret=None,
        timed_out=False,
        not_found=True,
        overflow=False,
    )
    assert "/nonexistent/steamos-mounter-probe: not found" in debug_log.text


@pytest.mark.parametrize(
    ("size", "overflow"), [(999, False), (1000, False), (1001, True), (100000, True)]
)
def test_stdout_cap_keeps_the_first_bytes_and_flags_overflow(size, overflow):
    result = run(SH, "-c", f"head -c {size} /dev/zero", stdout_cap=1000)

    assert (result.returncode, len(result.stdout), result.overflow) == (
        0,
        min(size, 1000),
        overflow,
    )


def test_overflow_is_logged(debug_log):
    run(SH, "-c", "head -c 10 /dev/zero", stdout_cap=4)

    assert "stdout cut at 4 bytes" in debug_log.text


def test_secret_stdout_returns_a_wrapper_and_never_logs_stdout(redacted_log):
    result = run(CAT, stdin=TEST_KEY, secret_stdout=True)
    try:
        wrapped = isinstance(result.secret, SecretBytes)
        same = wrapped and result.secret.reveal() == TEST_KEY
        output = redacted_log.getvalue()
        leaked = TEST_KEY.decode() in output or "[REDACTED]" in output
    finally:
        result.secret.clear()

    assert same
    assert not leaked
    assert result.stdout == b""
    assert f"{CAT}: 27 bytes of secret output" in output
    assert f"{CAT}: exit status 0" in output


# --- rule 6: logging ------------------------------------------------------------------


def test_argv_is_logged_before_the_run_and_output_after(debug_log):
    run(SH, "-c", "printf out; printf err >&2; exit 2")

    assert [record.getMessage() for record in debug_log.records] == [
        "run /bin/sh -c 'printf out; printf err >&2; exit 2'",
        "/bin/sh: exit status 2",
        "/bin/sh: stdout:\nout",
        "/bin/sh: stderr:\nerr",
    ]
    assert {record.levelno for record in debug_log.records} == {logging.DEBUG}


def test_log_output_false_logs_only_the_status(debug_log):
    run(SH, "-c", "printf DISPLAY=:0", log_output=False)

    assert [record.getMessage() for record in debug_log.records] == [
        "run /bin/sh -c 'printf DISPLAY=:0'",
        "/bin/sh: exit status 0",
    ]


def test_empty_output_is_not_logged(debug_log):
    run(SH, "-c", "true")

    assert len(debug_log.records) == 2


def test_timeout_is_logged(debug_log):
    run(SH, "-c", "exec sleep 30", timeout=0.1)

    assert "/bin/sh: timed out after 0.1 s" in debug_log.text


def test_stdin_is_never_logged(redacted_log):
    run(CAT, stdin=b"stdin-probe-31d9", log_output=False)

    assert "stdin-probe-31d9" not in redacted_log.getvalue()
