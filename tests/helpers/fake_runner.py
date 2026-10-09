"""A scripted stand-in for ``runner.Runner``.

Design Doc "Mock Boundary Decisions": external commands are faked at the one
subprocess seam, because Docker cannot mount, unlock or talk to systemd. Each
script matches commands by argv prefix or by a predicate and answers with
real Deck captures (``load_fixture`` plus the capture index's exit status) or
hand-built output.

The fake behaves like ``SubprocessRunner`` where a test could tell the
difference: it refuses the same commands (``check_command``: secrets, relative
``argv[0]``, bad environment names), wraps ``secret_stdout`` output in a
``SecretBytes`` and leaves stderr empty, and applies ``stdout_cap``.

Every accepted command lands in ``calls``. A command no script answers raises
``UnexpectedCommandError`` and is also kept in ``unexpected``, so a flow that
catches every exception at its top still fails the test at ``finish()``.
Hooks run outside the fake's lock, so two threads can meet at a
``threading.Barrier`` inside them (the J001 race).
"""

import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from steamos_mounter.runner import Command, CommandResult, check_command
from steamos_mounter.sensitive import SecretBytes
from tests.helpers.fixtures import fixture_rc, load_fixture

Match = str | Sequence[str] | Callable[[Command], bool]
Hook = Callable[[Command], None]


class UnexpectedCommandError(AssertionError):
    """A command no script answers, or one past a script's last answer."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Answer:
    """What one call returns; ``returncode`` None goes with a timeout or not-found."""

    stdout: bytes = b""
    stderr: bytes = b""
    returncode: int | None = 0
    timed_out: bool = False
    not_found: bool = False

    @classmethod
    def from_fixture(
        cls, name: str, *, returncode: int | None = None, stderr: bytes = b""
    ) -> "Answer":
        """Fixture bytes as stdout; the exit status from the capture index if None."""
        status = fixture_rc(name) if returncode is None else returncode
        return cls(stdout=load_fixture(name), stderr=stderr, returncode=status)

    @classmethod
    def timeout(cls) -> "Answer":
        return cls(returncode=None, timed_out=True)

    @classmethod
    def missing(cls) -> "Answer":
        return cls(returncode=None, not_found=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class Call:
    """One accepted command. ``stdin`` is kept out of repr and comparisons.

    It holds the bytes as passed at call time (a ``SecretBytes`` revealed), so
    a test can check what cryptsetup would have read by comparing booleans,
    without a failing assertion ever printing the key.
    """

    argv: tuple[str, ...]
    env_extra: Mapping[str, str]
    user: int | None
    group: int | None
    timeout: float
    has_stdin: bool
    secret_stdin: bool
    secret_stdout: bool
    log_output: bool
    stdin: bytes | None = field(default=None, repr=False, compare=False)


@dataclass(slots=True)
class _Script:
    match: Callable[[Command], bool]
    answers: list[Answer]
    hook: Hook | None
    repeat: bool
    used: int = 0

    def take(self) -> Answer | None:
        """The next answer, or None when the script has run out."""
        if self.used < len(self.answers):
            self.used += 1
            return self.answers[self.used - 1]
        return self.answers[-1] if self.repeat else None


class FakeRunner:
    """A ``Runner`` that answers from scripts and logs every call."""

    def __init__(self) -> None:
        self.calls: list[Call] = []
        self.unexpected: list[tuple[str, ...]] = []
        self._scripts: list[_Script] = []
        self._secrets: list[SecretBytes] = []
        self._lock = threading.Lock()

    def on(
        self,
        match: Match,
        *answers: Answer | str,
        hook: Hook | None = None,
        repeat: bool = False,
    ) -> None:
        """Answer matching commands with ``answers``, one per call, in order.

        ``match`` is ``argv[0]``, an argv prefix, or a predicate on the
        ``Command``. A ``str`` answer is a fixture name. Once the answers run
        out the script stops matching, unless ``repeat`` keeps returning the
        last one. The earliest script that matches and has an answer wins.
        """
        if not answers:
            raise ValueError("a script needs at least one answer")
        resolved = [
            Answer.from_fixture(item) if isinstance(item, str) else item
            for item in answers
        ]
        self._scripts.append(_Script(_matcher(match), resolved, hook, repeat))

    @property
    def argvs(self) -> list[tuple[str, ...]]:
        return [call.argv for call in self.calls]

    def run(self, cmd: Command) -> CommandResult:
        check_command(cmd)
        with self._lock:
            self.calls.append(_call(cmd))
            found = self._answer(cmd)
            if found is None:
                self.unexpected.append(tuple(cmd.argv))
                raise UnexpectedCommandError(f"no script answers {list(cmd.argv)}")
        hook, answer = found
        if hook is not None:
            hook(cmd)
        return self._result(cmd, answer)

    def finish(self) -> None:
        """Clear the secrets this fake made; fail when any command was unexpected."""
        for secret in self._secrets:
            secret.clear()
        if self.unexpected:
            raise UnexpectedCommandError(f"unexpected commands: {self.unexpected}")

    def _answer(self, cmd: Command) -> tuple[Hook | None, Answer] | None:
        for script in self._scripts:
            if script.match(cmd):
                answer = script.take()
                if answer is not None:
                    return script.hook, answer
        return None

    def _result(self, cmd: Command, answer: Answer) -> CommandResult:
        stdout = answer.stdout
        overflow = cmd.stdout_cap is not None and len(stdout) > cmd.stdout_cap
        if overflow:
            stdout = stdout[: cmd.stdout_cap]
        secret = None
        stderr = answer.stderr
        if cmd.secret_stdout:
            secret = SecretBytes(stdout)
            self._secrets.append(secret)
            stdout = b""
            stderr = b""
        return CommandResult(
            argv=tuple(cmd.argv),
            returncode=answer.returncode,
            stdout=stdout,
            stderr=stderr,
            secret=secret,
            timed_out=answer.timed_out,
            not_found=answer.not_found,
            overflow=overflow,
        )


def _matcher(match: Match) -> Callable[[Command], bool]:
    if callable(match):
        return match
    prefix = (match,) if isinstance(match, str) else tuple(match)
    return lambda cmd: tuple(cmd.argv[: len(prefix)]) == prefix


def _call(cmd: Command) -> Call:
    stdin = cmd.stdin.reveal() if isinstance(cmd.stdin, SecretBytes) else cmd.stdin
    return Call(
        argv=tuple(cmd.argv),
        env_extra=dict(cmd.env_extra),
        user=cmd.user,
        group=cmd.group,
        timeout=cmd.timeout,
        has_stdin=cmd.stdin is not None,
        secret_stdin=isinstance(cmd.stdin, SecretBytes),
        secret_stdout=cmd.secret_stdout,
        log_output=cmd.log_output,
        stdin=stdin,
    )
