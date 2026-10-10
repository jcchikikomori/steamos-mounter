"""Step lines, the report, and what ``install`` and ``uninstall`` share.

Design Doc "Python install (Install Equals Update)", "Python uninstall
(Unwire First, Then Stop)" and "Installer Contract for the Future Dotfiles
Wrapper". Split out of ``installer`` by step (Repository Layout rule).

Every step ends as one ``StepLine``, printed as
``steamos-mounter <command>: <step>: ok|skipped|failed|busy[: detail]``. A
step that raises ``MounterError`` or ``OSError`` is a failed line: its detail
is the generic message, the cause goes to the journal, and the run goes on
where that is safe. The report puts busy lines, then failed lines, last, so
the line the dotfiles wrapper's log tail shows is the one to act on. Exit
code: any failed line 5, else any busy line 6, else 0.
"""

import contextlib
import logging
import os
import shutil
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, TypeVar

from steamos_mounter import manifest
from steamos_mounter.errors import ExitCode, MounterError, ToolError
from steamos_mounter.journal import fields
from steamos_mounter.platforms import UNSUPPORTED_MESSAGE
from steamos_mounter.runner import Command

if TYPE_CHECKING:
    from steamos_mounter.context import Context

Status = Literal["ok", "skipped", "failed", "busy"]
T = TypeVar("T")

PREFIX: Final = "steamos-mounter"
INSTALL: Final = "install"
UNINSTALL: Final = "uninstall"
GUARDS: Final = "guards"
NEEDS_ROOT: Final = "needs root: run it with sudo"

OPT_DIR: Final = "/opt/steamos-mounter"
RELEASES_DIR: Final = f"{OPT_DIR}/releases"
CURRENT_LINK: Final = f"{OPT_DIR}/current"
RELEASE_PREFIX: Final = "releases/"
MANIFEST_FILE: Final = "data/manifest.tsv"
STATE_DIR: Final = "/var/lib/steamos-mounter"
KEPT_REGISTRY: Final = f"{STATE_DIR}/kept-config.toml"
RUNTIME_DIR: Final = "/run/steamos-mounter"
UDEVADM_TIMEOUT: Final = 30.0
# install.sh's umask; also set for the Python run itself (see fixed_umask).
INSTALL_UMASK: Final = 0o022
# Neither a release entry nor an installed directory may be writable by
# group or others (AC-039).
FORBIDDEN_BITS: Final = stat.S_IWGRP | stat.S_IWOTH
_DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class StepLine:
    step: str
    status: Status
    detail: str


@dataclass(frozen=True, slots=True)
class InstallReport:
    lines: tuple[StepLine, ...]
    exit_code: ExitCode


@dataclass(frozen=True, slots=True)
class Done:
    """How a step that did not raise ended."""

    status: Status
    detail: str = ""


def ok(detail: str = "") -> Done:
    return Done("ok", detail)


def skipped(detail: str = "") -> Done:
    return Done("skipped", detail)


def render(command: str, line: StepLine) -> str:
    """``steamos-mounter <command>: <step>: <status>[: <detail>]``."""
    text = f"{PREFIX} {command}: {line.step}: {line.status}"
    return f"{text}: {line.detail}" if line.detail else text


def refuse_guards(ctx: "Context") -> InstallReport | None:
    """Platform (exit 4), then root (exit 3), before anything is touched."""
    if not ctx.platform.detect(ctx.paths):
        line = StepLine(GUARDS, "failed", UNSUPPORTED_MESSAGE)
        return InstallReport((line,), ExitCode.UNSUPPORTED_PLATFORM)
    if ctx.euid != 0:
        line = StepLine(GUARDS, "failed", NEEDS_ROOT)
        return InstallReport((line,), ExitCode.NEEDS_ROOT)
    return None


@contextlib.contextmanager
def fixed_umask() -> Iterator[None]:
    """Run with umask 022 whatever the caller's, then restore it.

    ``install.sh`` sets 022, but ``sudo steamos-mounter install`` from a shell
    with umask 002 would otherwise get group-writable files the installer
    does not chmod itself (``compileall``'s ``__pycache__`` directories), and
    the entry point's trust check would then refuse the release as root.
    """
    previous = os.umask(INSTALL_UMASK)
    try:
        yield
    finally:
        os.umask(previous)


class Steps:
    """Collects the step lines of one run, logging each as it ends."""

    def __init__(self, command: str) -> None:
        self.command = command
        self._lines: list[StepLine] = []

    @property
    def failed(self) -> bool:
        return any(line.status == "failed" for line in self._lines)

    def add(self, step: str, status: Status, detail: str = "") -> None:
        self._lines.append(StepLine(step, status, detail))
        level = logging.ERROR if status == "failed" else logging.INFO
        log.log(
            level,
            "%s %s: %s %s",
            self.command,
            step,
            status,
            detail,
            extra=fields(event=self.command),
        )

    def run(self, step: str, body: Callable[[], Done]) -> bool:
        """Run ``body`` as ``step``; False when it failed."""
        return self.attempt(step, lambda: (body(), True)) is not None

    def attempt(self, step: str, body: Callable[[], tuple[Done, T]]) -> T | None:
        """Run ``body`` as ``step``; its value, or None when it failed."""
        try:
            done, value = body()
        except MounterError as error:
            self._fail(step, error.user_message, error.detail)
            return None
        except OSError as error:
            what = error.strerror or type(error).__name__
            where = f": {error.filename}" if error.filename else ""
            self._fail(step, f"{what}{where}", repr(error))
            return None
        self.add(step, done.status, done.detail)
        return value

    def report(self) -> InstallReport:
        """The lines, busy then failed ones last, and the exit code."""
        ordered = sorted(self._lines, key=_line_rank)
        if self.failed:
            code = ExitCode.PARTIAL
        elif any(line.status == "busy" for line in ordered):
            code = ExitCode.BUSY
        else:
            code = ExitCode.OK
        return InstallReport(tuple(ordered), code)

    def _fail(self, step: str, message: str, detail: str) -> None:
        log.error(
            "%s %s failed: %s",
            self.command,
            step,
            detail,
            extra=fields(event=self.command),
        )
        self.add(step, "failed", message)


def _line_rank(line: StepLine) -> int:
    """Stable sort key: busy lines after the others, failed lines last."""
    return {"busy": 1, "failed": 2}.get(line.status, 0)


# --- host operations both flows use -----------------------------------------------


def read_manifest(release: Path) -> tuple[manifest.Entry, ...]:
    """The release's ``data/manifest.tsv``; ``MounterError`` when unusable."""
    path = release / MANIFEST_FILE
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise MounterError(manifest.UNUSABLE, detail=f"{path}: {error}") from error
    return manifest.parse(text)


def ensure_dir(ctx: "Context", absolute: str, mode: int) -> bool:
    """Create ``absolute`` when missing, then set the trusted owner and ``mode``.

    The directory is opened with ``O_NOFOLLOW``, so a symlink in its place is
    an ``OSError``, never followed. True when anything changed.
    """
    path = ctx.paths.p(absolute)
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        changed = False
    else:
        changed = True
    uid, gid = ctx.platform.trusted_uid, os.getegid()
    fd = os.open(path, _DIR_FLAGS)
    try:
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid) != (uid, gid):
            os.fchown(fd, uid, gid)
            changed = True
        if stat.S_IMODE(info.st_mode) != mode:
            os.fchmod(fd, mode)  # mkdir applies the umask
            changed = True
    finally:
        os.close(fd)
    return changed


def udevadm_reload(ctx: "Context") -> Done:
    """``udevadm control --reload``; a failure raises ``ToolError``."""
    argv = (ctx.platform.tools.udevadm, "control", "--reload")
    result = ctx.runner.run(Command(argv=argv, timeout=UDEVADM_TIMEOUT))
    if result.returncode != 0:
        raise ToolError(
            "udev could not reload its rules",
            detail=(
                f"udevadm control --reload: exit {result.returncode}, timed out "
                f"{result.timed_out}: {result.err_text().strip()}"
            ),
        )
    return ok()


def file_rows(entries: tuple[manifest.Entry, ...]) -> tuple[manifest.Entry, ...]:
    return tuple(entry for entry in entries if entry.kind == "file")


def dir_rows(entries: tuple[manifest.Entry, ...]) -> tuple[manifest.Entry, ...]:
    return tuple(entry for entry in entries if entry.kind == "dir")


def row_mode(entry: manifest.Entry) -> int:
    """The row's mode; ``manifest.parse`` gives every ``dir``/``file`` row one."""
    if entry.mode is None:
        raise MounterError(manifest.UNUSABLE, detail=f"{entry.path}: no mode")
    return entry.mode


def dir_mode(entries: tuple[manifest.Entry, ...], absolute: str) -> int:
    """The mode of the manifest's ``dir`` row for ``absolute``."""
    for entry in dir_rows(entries):
        if entry.path == absolute:
            return row_mode(entry)
    raise MounterError(manifest.UNUSABLE, detail=f"no dir row for {absolute}")


def remove_path(path: Path) -> bool:
    """Remove a file, a symlink (never followed) or a tree; False when absent."""
    if not os.path.lexists(path):
        return False
    if path.is_symlink() or not path.is_dir():
        path.unlink()
    else:
        shutil.rmtree(path)
    return True


def is_runtime(absolute: str) -> bool:
    """A ``/run`` row: on tmpfs, made by ``records.ensure_runtime_dirs``."""
    return absolute == RUNTIME_DIR or absolute.startswith(f"{RUNTIME_DIR}/")
