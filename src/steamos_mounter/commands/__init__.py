"""The owner-facing commands, one module per command group (DD-27).

Design Doc "CLI Contract > Commands" and "Repository Layout". Each module
exports ``COMMANDS``, a tuple of ``Command``: its name, whether it needs
root, the exit codes its Commands row lists, how it adds its arguments, and
the body ``cli.main`` runs after the guards. A body returns the exit code of
a decided outcome and raises ``MounterError`` for every failure; ``cli``
turns that into the one generic error line (AC-042).
"""

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from steamos_mounter.errors import ExitCode
from steamos_mounter.output import Output

if TYPE_CHECKING:
    from steamos_mounter.context import Context


@dataclass(frozen=True, slots=True)
class Invocation:
    """One run of a command: the context, the parsed arguments, the terminal."""

    ctx: "Context"
    args: argparse.Namespace
    out: Output


@dataclass(frozen=True, slots=True)
class Command:
    """One row of the Commands table and its body."""

    name: str
    summary: str
    root_only: bool
    exit_codes: frozenset[ExitCode]
    configure: Callable[[argparse.ArgumentParser], None]
    run: Callable[[Invocation], ExitCode]
