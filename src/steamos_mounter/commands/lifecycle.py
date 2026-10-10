"""``install`` and ``uninstall``: thin wrappers over ``installer``.

Design Doc "CLI Contract > Commands" (``install [--release DIR] [--no-start]``,
``uninstall [--purge]``) and "Installer, Updater and Uninstaller". The steps
live in ``installer``; the wrappers only print its step lines, each with the
``steamos-mounter install:`` or ``steamos-mounter uninstall:`` prefix, and
return its exit code. Neither ever prompts or reads stdin.
"""

import argparse
from pathlib import Path
from typing import Final

from steamos_mounter import installer
from steamos_mounter.commands import Command, Invocation
from steamos_mounter.errors import ExitCode
from steamos_mounter.installer_report import INSTALL, UNINSTALL, InstallReport, render


def configure_install(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--release",
        metavar="DIR",
        help="the staged release to activate (install.sh passes it); "
        "without it the active release is repaired",
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="do not start instances for drives plugged in now",
    )


def configure_uninstall(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--purge",
        action="store_true",
        help="also delete the registry, the keys and /var/lib/steamos-mounter",
    )


def run_install(call: Invocation) -> ExitCode:
    release = None if call.args.release is None else Path(call.args.release)
    report = installer.install(
        call.ctx, release=release, start_present=not call.args.no_start
    )
    return _print(call, INSTALL, report)


def run_uninstall(call: Invocation) -> ExitCode:
    report = installer.uninstall(call.ctx, purge=call.args.purge)
    return _print(call, UNINSTALL, report)


def _print(call: Invocation, command: str, report: InstallReport) -> ExitCode:
    for line in report.lines:
        call.out.line(render(command, line))
    return report.exit_code


COMMANDS: Final[tuple[Command, ...]] = (
    Command(
        name=INSTALL,
        summary="install or update from a staged release (run by install.sh)",
        root_only=True,
        exit_codes=frozenset(
            {
                ExitCode.OK,
                ExitCode.USAGE,
                ExitCode.NEEDS_ROOT,
                ExitCode.UNSUPPORTED_PLATFORM,
                ExitCode.PARTIAL,
            }
        ),
        configure=configure_install,
        run=run_install,
    ),
    Command(
        name=UNINSTALL,
        summary="unwire, stop and remove everything; keep the registry and keys",
        root_only=True,
        exit_codes=frozenset(
            {
                ExitCode.OK,
                ExitCode.USAGE,
                ExitCode.NEEDS_ROOT,
                ExitCode.UNSUPPORTED_PLATFORM,
                ExitCode.PARTIAL,
                ExitCode.BUSY,
            }
        ),
        configure=configure_uninstall,
        run=run_uninstall,
    ),
)
