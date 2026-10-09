"""Host-side harness for the on-device E2E journeys (see tests/e2e/README.md).

Design Doc "On-device Verification Procedure", "Who does what": the owner runs
every sudo step and every physical action; the automated part only reads, over
SSH from the development host. The ``deck`` fixture enforces that split: it
runs a command on the Deck only when the command is, character for character,
one of the journey module's ``READ_ONLY_CHECKS``, the reachability check, or
one of the read-only ``sudo -n`` listings the journeys name. Anything else is
refused before a process starts.

The allow-list is imported from the journey module, not copied, so a check
added there is runnable here with no second edit.
"""

import os
import shlex
import subprocess
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import NoReturn

import pytest
from test_on_device_journeys import DEFAULT_SSH, PERSONAL_UUID, READ_ONLY_CHECKS

SSH_ENV = "STEAMOS_MOUNTER_DECK_SSH"
SSH_TIMEOUT_S = 60
REACHABILITY_CHECK = "true"
KEYS_DIR = "/var/lib/steamos-mounter/keys"

# The ssh prefix allow-list. Only these options are accepted, each value as a
# separate word; ``-o`` keys are compared case-insensitively, as ssh does.
SSH_FLAGS = frozenset({"-4", "-6", "-q"})
SSH_VALUE_OPTIONS = frozenset({"-p", "-i", "-l", "-F", "-o"})
STRICT_HOST_KEY_CHECKING = "stricthostkeychecking"
SSH_CONFIG_KEYS = frozenset(
    {"batchmode", "connecttimeout", STRICT_HOST_KEY_CHECKING, "userknownhostsfile"}
)
# Values that still verify a known host key; ``no``, ``off`` and ``ask`` do not
# (``ask`` would also wait on a prompt BatchMode cannot answer).
STRICT_HOST_KEY_CHECKING_VALUES = frozenset({"yes", "accept-new"})

# Root-only listings the journeys read (key dialog, remove/uninstall, Stage C).
# ``sudo -n`` never prompts: without a cached credential it exits 1 and runs
# nothing. None of them prints key bytes; ``stat`` reports owner and mode only.
READ_ONLY_SUDO_LISTINGS = {
    "keys": f"sudo -n ls -l {KEYS_DIR}",
    "config": "sudo -n cat /etc/steamos-mounter/config.toml",
    "key_modes": (
        f"sudo -n stat -c '%U %G %a %n' {KEYS_DIR} {KEYS_DIR}/{PERSONAL_UUID}.key"
    ),
}

ALLOWED_COMMANDS = frozenset(
    {
        REACHABILITY_CHECK,
        *READ_ONLY_CHECKS.values(),
        *READ_ONLY_SUDO_LISTINGS.values(),
    }
)

DeckRun = Callable[[str], subprocess.CompletedProcess[str]]


@pytest.fixture
def deck_ssh() -> str:
    """The SSH command prefix: STEAMOS_MOUNTER_DECK_SSH, else the documented one."""
    return os.environ.get(SSH_ENV, DEFAULT_SSH)


@pytest.fixture
def deck(deck_ssh: str) -> DeckRun:
    """Run one allow-listed read-only command on the Deck and return the result.

    The result is returned whatever the exit code (``check=False``): the
    journeys assert on ``returncode``, ``stdout`` and ``stderr`` themselves.
    stdin is closed so ssh never reads the terminal the owner answers on.
    """
    prefix_args = _ssh_prefix_args(deck_ssh)

    def run(command: str) -> subprocess.CompletedProcess[str]:
        if command not in ALLOWED_COMMANDS:
            raise ValueError(
                f"{command!r} is not an allowed read-only check; add it to "
                "READ_ONLY_CHECKS in test_on_device_journeys.py if it writes nothing"
            )
        return subprocess.run(
            [*prefix_args, command],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=SSH_TIMEOUT_S,
        )

    return run


def _ssh_prefix_args(prefix: str) -> list[str]:
    """Split the prefix and accept only ``ssh [allowed options] destination``.

    Refused: anything but ``ssh`` or an absolute path to it (the check would run
    on the host); options outside the allow-list (``-V`` and ``-G`` exit 0
    without connecting, ``-o ProxyCommand`` runs a local command,
    ``StrictHostKeyChecking=no`` skips the host key check); any word
    after the destination (it would run on the Deck before the checked
    command). Attached values (``-p2222``) are refused too: write ``-p 2222``.
    """
    args = shlex.split(prefix)
    if not args or not _is_ssh_program(args[0]):
        _refuse_prefix("the program must be ssh or an absolute path to ssh")
    destinations = _destination_positions(args[1:])
    if destinations != [len(args) - 2]:
        _refuse_prefix("it needs exactly one destination, as the last word")
    return args


def _is_ssh_program(program: str) -> bool:
    path = PurePosixPath(program)
    return program == "ssh" or (path.is_absolute() and path.name == "ssh")


def _destination_positions(words: list[str]) -> list[int]:
    """Validate every option word; return the positions of the other words."""
    destinations: list[int] = []
    index = 0
    while index < len(words):
        word = words[index]
        if word in SSH_FLAGS:
            index += 1
        elif word in SSH_VALUE_OPTIONS:
            if index + 1 >= len(words):
                _refuse_prefix("an option is missing its value")
            if word == "-o":
                _check_ssh_config_option(words[index + 1])
            index += 2
        elif word.startswith("-"):
            _refuse_prefix(
                "an option is outside the allow-list "
                "(attached values such as -p2222 must be written -p 2222)"
            )
        else:
            destinations.append(index)
            index += 1
    return destinations


def _check_ssh_config_option(option: str) -> None:
    key, separator, value = option.partition("=")
    if not separator or key.lower() not in SSH_CONFIG_KEYS:
        _refuse_prefix(
            "-o takes KEY=VALUE with BatchMode, ConnectTimeout, "
            "StrictHostKeyChecking or UserKnownHostsFile only"
        )
    if (
        key.lower() == STRICT_HOST_KEY_CHECKING
        and value.lower() not in STRICT_HOST_KEY_CHECKING_VALUES
    ):
        _refuse_prefix("StrictHostKeyChecking takes yes or accept-new only")


def _refuse_prefix(reason: str) -> NoReturn:
    # The value itself is not echoed: it is the owner's environment.
    raise ValueError(
        f"{SSH_ENV} is refused: {reason}. Expected: ssh [-4] [-6] [-q] [-p PORT] "
        "[-i FILE] [-l USER] [-F FILE] [-o KEY=VALUE] destination"
    )
