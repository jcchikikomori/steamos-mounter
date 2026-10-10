"""The owner-facing command line: ``steamos-mounter <command> [options]``.

Design Doc "CLI Contract" (Global Rules, Exit Codes, Commands), DD-03,
DD-05, DD-30, AC-012, AC-042 and AC-066. ``bin/steamos-mounter`` calls
``main`` with the active release; tests pass a ``Context`` and an
``Output``.

Order of a run:

1. ``internal …`` goes to ``unit_entry.main`` untouched, before the owner
   parser exists, so the verbs never show in ``--help`` (DD-03).
2. The arguments. ``--help`` and ``--version`` answer here and pass no
   guard. argparse never prints or exits by itself: its help text goes
   through ``Output``, and a parse error is a ``UsageError`` (exit 2) held
   back until the platform guard ran.
3. Guards, before any write and any ``systemctl`` call: platform (exit 4),
   then root for a root-only command (exit 3), so a ``deck`` run never
   triggers a polkit prompt (AC-066).
4. The context: ``build_context`` sets up logging (``SM_COMPONENT=cli``)
   and, as root, the ``/run/steamos-mounter`` tree; an injected ``ctx``
   gets the tree step here.
5. The command, from the ``commands`` tables. Its start and outcome are
   logged at NOTICE or higher with ``SM_EVENT=<command>``. A failure is one
   generic line on stderr, ``steamos-mounter: <what failed>. <next step>.
   Details: journalctl -t steamos-mounter``; the detail and any traceback
   go to the journal only (AC-042).

Keys are never options (AC-012): ``--key-file`` and ``--key-stdin`` exist,
abbreviations are off, and an unrecognized argument is never echoed back,
so a key typed as an option reaches neither the terminal nor the journal.
"""

import argparse
import functools
import logging
import re
import sys
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any, NoReturn

from steamos_mounter import __version__, records, unit_entry
from steamos_mounter.commands import Command, Invocation, lifecycle, mounting, register
from steamos_mounter.context import Context, build_context
from steamos_mounter.errors import ExitCode, MounterError, UsageError
from steamos_mounter.journal import NOTICE, fields
from steamos_mounter.output import Output
from steamos_mounter.platforms import UNSUPPORTED_MESSAGE
from steamos_mounter.unit_entry import GuardFacts, guard_facts

PROG = "steamos-mounter"
COMPONENT = "cli"
DETAILS = "Details: journalctl -t steamos-mounter"
INTERNAL_ERROR = "internal error. Run it again; if it fails again, see the journal"
NEEDS_ROOT = "{command} needs root: run it with sudo"
NO_COMMAND = "a command is required"
HELP_HINT = "Run steamos-mounter --help"
UNRECOGNIZED = "unrecognized arguments"
COMMANDS: tuple[Command, ...] = (
    *register.COMMANDS,
    *mounting.COMMANDS,
    *lifecycle.COMMANDS,
)
BY_NAME: Mapping[str, Command] = MappingProxyType(
    {command.name: command for command in COMMANDS}
)
# argparse may color its help on a terminal (Python 3.14); output stays plain.
_ANSI_SGR = re.compile(r"\x1b\[[0-9;]*m")

log = logging.getLogger(__name__)


class _ParserExitError(Exception):
    """argparse is done early (``--help``): the text is in the sink."""


class _Parser(argparse.ArgumentParser):
    """An ``ArgumentParser`` that neither prints nor exits."""

    def __init__(self, *args: Any, sink: list[str], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._sink = sink

    def print_help(self, file: object = None) -> None:
        self._sink.append(self.format_help())

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        raise _ParserExitError

    def error(self, message: str) -> NoReturn:
        # Never echo what was not understood: it may be a key typed as an option.
        if message.startswith(UNRECOGNIZED):
            message = UNRECOGNIZED
        raise UsageError(f"{message}. {HELP_HINT}", detail=f"usage: {message}")


Parsed = argparse.Namespace | tuple[str, ...] | UsageError


def build_parser(sink: list[str]) -> argparse.ArgumentParser:
    """The owner parser: one subcommand per ``COMMANDS`` row, no ``internal``."""
    factory = functools.partial(_Parser, sink=sink, allow_abbrev=False)
    parser = factory(
        prog=PROG,
        description="Mount external drives on SteamOS at plug-in and boot.",
    )
    parser.add_argument("--version", action="store_true", help="print the version")
    subcommands = parser.add_subparsers(
        dest="command", metavar="COMMAND", parser_class=factory
    )
    for command in COMMANDS:
        sub = subcommands.add_parser(
            command.name, help=command.summary, description=command.summary
        )
        command.configure(sub)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    release_root: str | None = None,
    ctx: Context | None = None,
    out: Output | None = None,
) -> int:
    """Run one owner command; the exit code of the CLI Contract's table."""
    words = list(sys.argv[1:] if argv is None else argv)
    if words[:1] == [unit_entry.INTERNAL]:
        return unit_entry.main(words, ctx=ctx)
    output = out or Output()
    parsed = _parse(words)
    if isinstance(parsed, tuple):
        _print_text(output, parsed)
        return ExitCode.OK
    refused = _guard(guard_facts(ctx), parsed)
    if refused is not None:
        code, message = refused
        output.error(message)
        return code
    command = BY_NAME[parsed.command]
    try:
        ready = _context(ctx, release_root)
    except MounterError as error:
        return _failed(output, command.name, error)
    return _run(command, Invocation(ready, parsed, output))


def _parse(words: list[str]) -> Parsed:
    """The arguments, the ``--help``/``--version`` text, or a held-back error."""
    sink: list[str] = []
    try:
        args = build_parser(sink).parse_args(words)
    except _ParserExitError:
        return tuple(sink)
    except UsageError as error:
        return error
    if args.version:
        return (f"{PROG} {__version__}",)
    if args.command is None:
        return UsageError(f"{NO_COMMAND}. {HELP_HINT}")
    return args


def _print_text(output: Output, texts: tuple[str, ...]) -> None:
    for text in texts:
        for line in _ANSI_SGR.sub("", text).rstrip("\n").split("\n"):
            output.line(line)


def _guard(
    facts: GuardFacts, parsed: argparse.Namespace | UsageError
) -> tuple[ExitCode, str] | None:
    """Platform, then a parse error, then root (DD-30); None: all pass."""
    if not facts.on_platform:
        return ExitCode.UNSUPPORTED_PLATFORM, f"{UNSUPPORTED_MESSAGE}."
    if isinstance(parsed, UsageError):
        return parsed.exit_code, f"{parsed.user_message}."
    if BY_NAME[parsed.command].root_only and facts.euid != 0:
        return ExitCode.NEEDS_ROOT, f"{NEEDS_ROOT.format(command=parsed.command)}."
    return None


def _context(ctx: Context | None, release_root: str | None) -> Context:
    if ctx is None:
        return build_context(component=COMPONENT, release_root=release_root)
    records.ensure_runtime_dirs(ctx)
    return ctx


def _run(command: Command, call: Invocation) -> int:
    name = command.name
    log.log(NOTICE, "%s started", name, extra=fields(event=name))
    try:
        code = command.run(call)
    except MounterError as error:
        return _failed(call.out, name, error)
    except Exception as error:  # the one top-level catch: a generic line, exit 1
        log.error(
            "%s failed: internal error",
            name,
            exc_info=error,
            extra=fields(event=name, reason="internal_error"),
        )
        call.out.error(_line(INTERNAL_ERROR))
        return ExitCode.FAILED
    level = NOTICE if code == ExitCode.OK else logging.WARNING
    log.log(level, "%s finished: exit %d", name, code, extra=fields(event=name))
    return code


def _failed(output: Output, name: str, error: MounterError) -> int:
    log.error(
        "%s failed (exit %d): %s %s",
        name,
        error.exit_code,
        error.user_message,
        error.detail,
        extra=fields(event=name, volume=error.volume),
    )
    output.error(_line(error.user_message))
    return error.exit_code


def _line(message: str) -> str:
    """``<what failed>. <next step>. Details: journalctl -t steamos-mounter``."""
    text = message.rstrip()
    if not text.endswith("."):
        text += "."
    return f"{text} {DETAILS}"
