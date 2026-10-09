"""Exit codes and the exception hierarchy.

``ExitCode`` is the CLI Contract's Exit Codes table. Every ``MounterError``
subclass names the code it maps to. ``user_message`` is the short, generic
text for the terminal; ``detail`` is for the journal only (ADR-COMMON-0001),
so ``str()`` of an error never includes it.
"""

from enum import IntEnum
from typing import ClassVar


class ExitCode(IntEnum):
    OK = 0
    FAILED = 1
    USAGE = 2
    NEEDS_ROOT = 3
    UNSUPPORTED_PLATFORM = 4
    PARTIAL = 5
    BUSY = 6
    NOT_PRESENT = 7
    REFUSED = 8


class MounterError(Exception):
    """A decided failure with a generic message and a journal-only detail."""

    exit_code: ClassVar[ExitCode] = ExitCode.FAILED

    def __init__(
        self, user_message: str, *, detail: str = "", volume: str | None = None
    ) -> None:
        super().__init__(user_message)
        self.user_message = user_message
        self.detail = detail
        self.volume = volume


class UsageError(MounterError):
    """Bad arguments, unknown volume name, or no terminal for a hidden prompt."""

    exit_code: ClassVar[ExitCode] = ExitCode.USAGE


class NeedsRootError(MounterError):
    """A root-only command ran without root; nothing changed."""

    exit_code: ClassVar[ExitCode] = ExitCode.NEEDS_ROOT


class UnsupportedPlatformError(MounterError):
    """The host is not SteamOS; nothing changed."""

    exit_code: ClassVar[ExitCode] = ExitCode.UNSUPPORTED_PLATFORM


class NotPresentError(MounterError):
    """The volume or device is not attached."""

    exit_code: ClassVar[ExitCode] = ExitCode.NOT_PRESENT


class RefusedError(MounterError):
    """Policy said no (ext4, OS partition, duplicate, wrong key, ...)."""

    exit_code: ClassVar[ExitCode] = ExitCode.REFUSED


class RegistryError(MounterError):
    """The registry file is unusable."""


class ToolError(MounterError):
    """An external command failed unexpectedly."""


# The Design Doc fixes this public name (AC-030), so it keeps no Error suffix.
class InvalidKernelName(MounterError):  # noqa: N818
    """A kernel device name failed validation."""


class SecretHandlingError(RuntimeError):
    """Programming error: a secret reached argv or the environment."""
