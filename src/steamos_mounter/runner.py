"""The single subprocess seam: every external command runs through here.

ADR-COMMON-0001 decision 5 and the Design Doc section "runner (the single
subprocess seam)". ``SubprocessRunner.run`` enforces, in this order:

1. No secret in argv or the environment: a ``SecretBytes``, or the bytes or
   text of any live secret, raises ``SecretHandlingError`` before anything
   about the command is logged.
2. ``argv[0]`` is absolute; ``env_extra`` names match ``^[A-Z_][A-Z0-9_]*$``.
3. The environment is ``BASE_ENV | env_extra``; nothing is inherited, so a
   ``sudo`` from the owner's shell and a unit started by systemd run tools the
   same way. ``LC_ALL=C.UTF-8`` (DD-01) replaces the ADR's ``LC_ALL=C``, so
   libsmartcols prints real UTF-8 instead of ``\\xNN`` text.
4. The child gets its own process group, no inherited descriptors, and, when a
   uid switch is asked for, no supplementary groups.
5. stdin is written and closed, then the child gets ``timeout`` seconds to
   exit. stdout and stderr are read the whole time, so a large output cannot
   stall it. After the exit the pipes are drained for at most 0.5 s (DD-14):
   ntfs-3g daemonizes and its daemon keeps them open. On timeout the group
   gets SIGTERM, then SIGKILL after a grace period.
6. argv is logged at DEBUG before the run; the exit status and, when
   ``log_output``, the decoded output after it. stdin is never logged; for a
   ``secret_stdout`` call only the exit status and the byte count are.

Output stays bytes; ``CommandResult.text`` decodes UTF-8 with
``surrogateescape``, so an undecodable label byte survives instead of raising.
This module is the only importer of ``subprocess`` (ruff TID251).
"""

import contextlib
import logging
import os
import re
import selectors
import shlex
import signal
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import IO, Final, Protocol

from steamos_mounter.errors import SecretHandlingError
from steamos_mounter.sensitive import SecretBytes, live_secrets, redact_text

BASE_ENV: Final[Mapping[str, str]] = MappingProxyType(
    {"LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/usr/sbin"}
)
ENV_NAME: Final = re.compile(r"[A-Z_][A-Z0-9_]*")
TEXT_ERRORS: Final = "surrogateescape"
# DD-14: how long the pipes may stay open after the child exited.
DRAIN_LIMIT = 0.5
# Seconds between SIGTERM and SIGKILL, and after SIGKILL, on a timeout.
TERM_GRACE = 2.0
KILL_GRACE = 2.0
_CHUNK: Final = 1 << 16
# Selector tags for the two non-output descriptors.
_EXIT: Final = "exit"
_STDIN: Final = "stdin"

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True, kw_only=True)
class Command:
    """One external command and how to run it."""

    argv: tuple[str, ...]
    timeout: float
    stdin: bytes | SecretBytes | None = None
    env_extra: Mapping[str, str] = field(default_factory=dict)
    user: int | None = None
    group: int | None = None
    secret_stdout: bool = False
    stdout_cap: int | None = None
    log_output: bool = True


@dataclass(frozen=True, slots=True)
class CommandResult:
    """What a command did. ``returncode`` is None when it timed out or was not found."""

    argv: tuple[str, ...]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    secret: SecretBytes | None
    timed_out: bool
    not_found: bool
    overflow: bool

    def text(self) -> str:
        return self.stdout.decode("utf-8", TEXT_ERRORS)

    def err_text(self) -> str:
        return self.stderr.decode("utf-8", TEXT_ERRORS)


class Runner(Protocol):
    def run(self, cmd: Command) -> CommandResult: ...


def check_command(cmd: Command) -> None:
    """Rules 1 and 2, shared with the test fake so both refuse the same commands.

    Secrets are checked first, so no other message can echo one.
    """
    for index, item in enumerate(cmd.argv):
        if _holds_secret(item):
            raise SecretHandlingError(f"a secret is in argv[{index}]")
    for name, value in cmd.env_extra.items():
        if _holds_secret(name) or _holds_secret(value):
            raise SecretHandlingError("a secret is in the environment")
    if not all(isinstance(item, str) for item in cmd.argv):
        raise TypeError("argv items must be str")
    if not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in cmd.env_extra.items()
    ):
        raise TypeError("environment names and values must be str")
    if not cmd.argv or not os.path.isabs(cmd.argv[0]):
        raise ValueError(f"argv[0] must be an absolute path: {cmd.argv[:1]!r}")
    for name in cmd.env_extra:
        if not ENV_NAME.fullmatch(name):
            raise ValueError(f"invalid environment variable name {name!r}")


def _holds_secret(value: object) -> bool:
    if isinstance(value, SecretBytes):
        return True
    if isinstance(value, bytes | bytearray):
        return any(secret in value for secret in live_secrets() if secret)
    if isinstance(value, str):
        # redact_text changes a string exactly when a live secret is in it.
        return redact_text(value) != value
    return False


class SubprocessRunner:
    """The production ``Runner``."""

    def run(self, cmd: Command) -> CommandResult:
        check_command(cmd)
        log.debug("run %s", shlex.join(cmd.argv))
        try:
            process = subprocess.Popen(cmd.argv, **_popen_options(cmd))
        except FileNotFoundError:
            log.debug("%s: not found", cmd.argv[0])
            return CommandResult(
                argv=tuple(cmd.argv),
                returncode=None,
                stdout=b"",
                stderr=b"",
                secret=None,
                timed_out=False,
                not_found=True,
                overflow=False,
            )
        streams = _Streams(process, cmd)
        try:
            exited = _wait_for_exit(process, streams, time.monotonic() + cmd.timeout)
            streams.drain(DRAIN_LIMIT)
        finally:
            streams.close()
        result = _result(cmd, process, streams, timed_out=not exited)
        _log_result(cmd, result)
        return result


def _popen_options(cmd: Command) -> dict[str, object]:
    options: dict[str, object] = {
        "stdin": subprocess.DEVNULL if cmd.stdin is None else subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL if cmd.secret_stdout else subprocess.PIPE,
        "env": dict(BASE_ENV) | dict(cmd.env_extra),
        "close_fds": True,
        "process_group": 0,
        "user": cmd.user,
        "group": cmd.group,
    }
    if cmd.user is not None:
        options["extra_groups"] = []
    return options


def _wait_for_exit(
    process: subprocess.Popen[bytes], streams: "_Streams", deadline: float
) -> bool:
    """True when the child exited in time; otherwise its group is stopped.

    The child runs in its own process group, so a Ctrl-C at the terminal does
    not reach it; any exception while waiting stops the group before it
    propagates.
    """
    try:
        exited = streams.serve_until_exit(deadline)
    except BaseException:
        _stop_group(process)
        raise
    if exited:
        process.wait()
    else:
        _stop_group(process)
    return exited


def _stop_group(process: subprocess.Popen[bytes]) -> None:
    _signal_group(process.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(TERM_GRACE)
    _signal_group(process.pid, signal.SIGKILL)
    try:
        process.wait(KILL_GRACE)
    except subprocess.TimeoutExpired:
        log.warning("process group %d still runs after SIGKILL", process.pid)


def _signal_group(group: int, signum: signal.Signals) -> None:
    # ProcessLookupError: every member already exited.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(group, signum)


class _Streams:
    """Feeds stdin and collects stdout and stderr without blocking on any of them.

    A pidfd in the same selector reports the child's exit, so the wait and
    the pipe traffic share one loop and one deadline.
    """

    def __init__(self, process: subprocess.Popen[bytes], cmd: Command) -> None:
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.overflow = False
        self._process = process
        self._cap = cmd.stdout_cap
        stdin = cmd.stdin.reveal() if isinstance(cmd.stdin, SecretBytes) else cmd.stdin
        self._pending = memoryview(stdin or b"")
        self._selector = selectors.DefaultSelector()
        self._exit_fd = os.pidfd_open(process.pid)
        self._selector.register(self._exit_fd, selectors.EVENT_READ, _EXIT)
        if process.stdin is not None:
            os.set_blocking(process.stdin.fileno(), False)
            self._selector.register(process.stdin, selectors.EVENT_WRITE, _STDIN)
        self._selector.register(process.stdout, selectors.EVENT_READ, self.stdout)
        if process.stderr is not None:
            self._selector.register(process.stderr, selectors.EVENT_READ, self.stderr)

    def serve_until_exit(self, deadline: float) -> bool:
        """Move data until the child exits (True) or the deadline passes (False)."""
        while (remaining := deadline - time.monotonic()) > 0:
            for key, _events in self._selector.select(remaining):
                if key.data is _EXIT:
                    return True
                self._serve(key)
        return False

    def drain(self, limit: float) -> None:
        """Move data until every pipe is closed or ``limit`` seconds pass (DD-14)."""
        self._selector.unregister(self._exit_fd)
        deadline = time.monotonic() + limit
        while self._selector.get_map() and (
            (remaining := deadline - time.monotonic()) > 0
        ):
            for key, _events in self._selector.select(remaining):
                self._serve(key)

    def close(self) -> None:
        self._selector.close()
        os.close(self._exit_fd)
        self._pending = memoryview(b"")
        for pipe in (self._process.stdin, self._process.stdout, self._process.stderr):
            if pipe is not None:
                pipe.close()

    def _serve(self, key: selectors.SelectorKey) -> None:
        if key.data is _STDIN:
            self._write(key.fileobj)
        else:
            self._read(key.fileobj, key.data)

    def _write(self, pipe: IO[bytes]) -> None:
        try:
            written = os.write(pipe.fileno(), self._pending[:_CHUNK])
        except BrokenPipeError:
            # The child closed its stdin unread; the rest has nowhere to go.
            written = len(self._pending)
        self._pending = self._pending[written:]
        if not self._pending:
            self._selector.unregister(pipe)
            pipe.close()

    def _read(self, pipe: IO[bytes], buffer: bytearray) -> None:
        chunk = os.read(pipe.fileno(), _CHUNK)
        if not chunk:
            self._selector.unregister(pipe)
            return
        if buffer is self.stdout and self._cap is not None:
            room = self._cap - len(buffer)
            if len(chunk) > room:
                self.overflow = True
                chunk = chunk[:room]
        buffer += chunk


def _result(
    cmd: Command,
    process: subprocess.Popen[bytes],
    streams: _Streams,
    *,
    timed_out: bool,
) -> CommandResult:
    if cmd.secret_stdout:
        secret = SecretBytes(streams.stdout)
        streams.stdout[:] = bytes(len(streams.stdout))
        stdout = b""
    else:
        secret = None
        stdout = bytes(streams.stdout)
    return CommandResult(
        argv=tuple(cmd.argv),
        returncode=None if timed_out else process.returncode,
        stdout=stdout,
        stderr=bytes(streams.stderr),
        secret=secret,
        timed_out=timed_out,
        not_found=False,
        overflow=streams.overflow,
    )


def _log_result(cmd: Command, result: CommandResult) -> None:
    name = cmd.argv[0]
    if result.timed_out:
        log.debug("%s: timed out after %s s", name, cmd.timeout)
    else:
        log.debug("%s: exit status %s", name, result.returncode)
    if result.overflow:
        log.debug("%s: stdout cut at %s bytes", name, cmd.stdout_cap)
    if result.secret is not None:
        log.debug("%s: %d bytes of secret output", name, len(result.secret))
        return
    if not cmd.log_output:
        return
    if result.stdout:
        log.debug("%s: stdout:\n%s", name, result.text())
    if result.stderr:
        log.debug("%s: stderr:\n%s", name, result.err_text())
