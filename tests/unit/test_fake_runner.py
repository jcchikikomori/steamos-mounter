"""Self-tests for tests/helpers/fake_runner.py.

Design Doc: docs/design/steamos-mounter-design.md (sections "Mock Boundary
Decisions" and "runner (the single subprocess seam)"). Nearly every later test
stands on this fake, so it is checked here: matching, sequential answers,
fixture answers with the capture index's exit status, the call log, hooks
(including two threads meeting at a ``Barrier``, as the J001 race does), and
failure on any unexpected command. Where ``SubprocessRunner`` refuses or
reshapes a command, the fake must do the same.
"""

import contextlib
import threading

import pytest

from steamos_mounter.errors import SecretHandlingError
from steamos_mounter.runner import Command, CommandResult
from steamos_mounter.sensitive import SecretBytes, live_secrets
from tests.helpers.fake_runner import Answer, Call, FakeRunner, UnexpectedCommandError
from tests.helpers.fixtures import load_fixture

LSBLK = "/usr/bin/lsblk"
FINDMNT = "/usr/bin/findmnt"
TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"


def cmd(*argv: str, **options: object) -> Command:
    options.setdefault("timeout", 5.0)
    return Command(argv=argv, **options)


def test_unexpected_command_raises_and_fails_finish():
    runner = FakeRunner()

    with pytest.raises(UnexpectedCommandError, match="no script answers"):
        runner.run(cmd(LSBLK, "-J"))

    assert runner.unexpected == [(LSBLK, "-J")]
    with pytest.raises(UnexpectedCommandError, match="unexpected commands"):
        runner.finish()


def test_unexpected_command_swallowed_by_the_caller_still_fails_finish():
    runner = FakeRunner()

    with contextlib.suppress(UnexpectedCommandError):
        runner.run(cmd(LSBLK))

    with pytest.raises(UnexpectedCommandError):
        runner.finish()


def test_finish_passes_when_every_command_was_answered():
    runner = FakeRunner()
    runner.on(LSBLK, Answer(stdout=b"{}"))
    runner.run(cmd(LSBLK))

    assert runner.finish() is None


def test_argv0_match_answers_any_arguments():
    runner = FakeRunner()
    runner.on(LSBLK, Answer(stdout=b"out"), repeat=True)

    first = runner.run(cmd(LSBLK, "-J"))
    second = runner.run(cmd(LSBLK))

    assert (first.stdout, second.stdout) == (b"out", b"out")


def test_prefix_match_needs_every_prefix_item():
    runner = FakeRunner()
    runner.on([FINDMNT, "-J", "--target"], Answer(stdout=b"hit"))

    with pytest.raises(UnexpectedCommandError):
        runner.run(cmd(FINDMNT, "-J"))
    result = runner.run(cmd(FINDMNT, "-J", "--target", "/run/media/x"))

    assert result.stdout == b"hit"


def test_predicate_match_sees_the_whole_command():
    runner = FakeRunner()
    runner.on(lambda command: command.user == 1000, Answer(stdout=b"as deck"))

    result = runner.run(cmd("/usr/bin/id", user=1000))

    assert result.stdout == b"as deck"


def test_sequential_answers_for_the_same_argv_then_unexpected():
    runner = FakeRunner()
    runner.on(FINDMNT, Answer(returncode=1), Answer(stdout=b"mounted"))

    first = runner.run(cmd(FINDMNT))
    second = runner.run(cmd(FINDMNT))
    with pytest.raises(UnexpectedCommandError):
        runner.run(cmd(FINDMNT))

    assert (first.returncode, second.returncode, second.stdout) == (1, 0, b"mounted")


def test_repeat_keeps_returning_the_last_answer():
    runner = FakeRunner()
    runner.on(FINDMNT, Answer(returncode=1), Answer(returncode=0), repeat=True)

    codes = [runner.run(cmd(FINDMNT)).returncode for _ in range(4)]

    assert codes == [1, 0, 0, 0]


def test_earliest_script_with_answers_wins_then_the_next_one():
    runner = FakeRunner()
    runner.on(LSBLK, Answer(stdout=b"first"))
    runner.on(LSBLK, Answer(stdout=b"second"))

    outputs = [runner.run(cmd(LSBLK)).stdout for _ in range(2)]

    assert outputs == [b"first", b"second"]


def test_script_needs_an_answer():
    with pytest.raises(ValueError, match="at least one answer"):
        FakeRunner().on(LSBLK)


def test_fixture_answer_uses_the_capture_and_its_index_rc():
    runner = FakeRunner()
    runner.on(FINDMNT, "findmnt-sdb5-not-mounted.json")

    result = runner.run(cmd(FINDMNT))

    assert result.stdout == load_fixture("findmnt-sdb5-not-mounted.json")
    assert result.returncode == 1


def test_fixture_answer_with_an_explicit_returncode_and_stderr():
    answer = Answer.from_fixture("lsblk-full.json", returncode=32, stderr=b"warn")

    assert (answer.returncode, answer.stderr) == (32, b"warn")
    assert answer.stdout == load_fixture("lsblk-full.json")


def test_fixture_answer_without_an_index_row_needs_a_returncode():
    with pytest.raises(KeyError):
        Answer.from_fixture("evidence/no-such-capture.txt")


def test_timeout_and_missing_answers():
    runner = FakeRunner()
    runner.on(LSBLK, Answer.timeout(), Answer.missing())

    timed_out = runner.run(cmd(LSBLK))
    missing = runner.run(cmd(LSBLK))

    assert (timed_out.timed_out, timed_out.returncode) == (True, None)
    assert (missing.not_found, missing.returncode) == (True, None)


def test_result_mirrors_the_command():
    runner = FakeRunner()
    runner.on(LSBLK, Answer(stdout=b"o", stderr=b"e", returncode=2))

    result = runner.run(cmd(LSBLK, "-J"))

    assert result == CommandResult(
        argv=(LSBLK, "-J"),
        returncode=2,
        stdout=b"o",
        stderr=b"e",
        secret=None,
        timed_out=False,
        not_found=False,
        overflow=False,
    )


@pytest.mark.parametrize(("size", "overflow"), [(4, False), (5, True)])
def test_stdout_cap_truncates_like_the_real_runner(size, overflow):
    runner = FakeRunner()
    runner.on(LSBLK, Answer(stdout=b"x" * size))

    result = runner.run(cmd(LSBLK, stdout_cap=4))

    assert (result.stdout, result.overflow) == (b"x" * min(size, 4), overflow)


def test_secret_stdout_is_wrapped_and_cleared_at_finish():
    runner = FakeRunner()
    runner.on("/usr/bin/kdialog", Answer(stdout=TEST_KEY, stderr=b"noise"))

    result = runner.run(cmd("/usr/bin/kdialog", "--password", "x", secret_stdout=True))
    wrapped = result.secret.reveal() == TEST_KEY
    runner.finish()
    cleared = TEST_KEY not in live_secrets()

    assert wrapped
    assert cleared
    assert (result.stdout, result.stderr) == (b"", b"")


def test_call_log_records_every_command():
    runner = FakeRunner()
    runner.on(lambda command: True, Answer(), repeat=True)
    secret = SecretBytes(TEST_KEY)
    try:
        runner.run(cmd(LSBLK, "-J"))
        runner.run(
            cmd(
                "/usr/sbin/cryptsetup",
                "open",
                stdin=secret,
                env_extra={"DISPLAY": ":0"},
                user=1000,
                group=1000,
                timeout=30.0,
            )
        )
        runner.run(cmd("/usr/bin/kdialog", secret_stdout=True, log_output=False))
        stdin_held = runner.calls[1].stdin == TEST_KEY
    finally:
        secret.clear()
        runner.finish()

    assert runner.calls == [
        Call(
            argv=(LSBLK, "-J"),
            env_extra={},
            user=None,
            group=None,
            timeout=5.0,
            has_stdin=False,
            secret_stdin=False,
            secret_stdout=False,
            log_output=True,
        ),
        Call(
            argv=("/usr/sbin/cryptsetup", "open"),
            env_extra={"DISPLAY": ":0"},
            user=1000,
            group=1000,
            timeout=30.0,
            has_stdin=True,
            secret_stdin=True,
            secret_stdout=False,
            log_output=True,
        ),
        Call(
            argv=("/usr/bin/kdialog",),
            env_extra={},
            user=None,
            group=None,
            timeout=5.0,
            has_stdin=False,
            secret_stdin=False,
            secret_stdout=True,
            log_output=False,
        ),
    ]
    assert stdin_held
    assert runner.argvs == [
        (LSBLK, "-J"),
        ("/usr/sbin/cryptsetup", "open"),
        ("/usr/bin/kdialog",),
    ]


def test_call_repr_never_shows_stdin():
    runner = FakeRunner()
    runner.on(LSBLK, Answer())

    runner.run(cmd(LSBLK, stdin=b"stdin-probe-31d9"))

    assert "stdin-probe-31d9" not in repr(runner.calls[0])


def test_hook_runs_with_the_command_before_the_result_returns():
    runner = FakeRunner()
    seen: list[tuple[str, ...]] = []
    runner.on(LSBLK, Answer(), hook=lambda command: seen.append(command.argv))

    runner.run(cmd(LSBLK, "-J"))

    assert seen == [(LSBLK, "-J")]


def test_hooks_of_two_threads_can_meet_at_a_barrier():
    runner = FakeRunner()
    barrier = threading.Barrier(2, timeout=5.0)
    runner.on(LSBLK, Answer(), hook=lambda command: barrier.wait(), repeat=True)
    results: list[CommandResult] = []

    threads = [
        threading.Thread(target=lambda: results.append(runner.run(cmd(LSBLK))))
        for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10.0)

    assert [result.returncode for result in results] == [0, 0]
    assert not barrier.broken
    assert len(runner.calls) == 2


def test_fake_refuses_a_secret_in_argv_like_the_real_runner():
    runner = FakeRunner()
    runner.on(lambda command: True, Answer(), repeat=True)
    secret = SecretBytes(TEST_KEY)
    try:
        with pytest.raises(SecretHandlingError):
            runner.run(cmd("/usr/sbin/cryptsetup", "open", TEST_KEY.decode()))
    finally:
        secret.clear()

    assert runner.calls == []


def test_fake_refuses_a_relative_argv0_like_the_real_runner():
    runner = FakeRunner()
    runner.on(lambda command: True, Answer(), repeat=True)

    with pytest.raises(ValueError, match="absolute path"):
        runner.run(cmd("lsblk"))

    assert runner.calls == []


def test_fake_runner_fixture_starts_empty(fake_runner):
    assert isinstance(fake_runner, FakeRunner)
    assert (fake_runner.calls, fake_runner.unexpected) == ([], [])
