"""Host-side E2E harness: the Deck reachability smoke test and the allow-list.

``test_deck_reachable`` runs ``true`` over SSH and is skipped unless
STEAMOS_MOUNTER_DECK=1 is set, like the journeys. It sorts before
``test_on_device_journeys.py``, so a full host run checks the connection first.

The other tests are Docker-safe: they stub ``subprocess.run`` and prove that the
``deck`` fixture (tests/e2e/conftest.py) only sends read-only commands to the
Deck and refuses everything else before any process starts.
"""

import os
import re
import subprocess
from collections.abc import Callable
from typing import Any

import pytest
from test_on_device_journeys import READ_ONLY_CHECKS

FAKE_PREFIX = "ssh -o BatchMode=yes -p 2222 deck@deck.invalid"
FAKE_PREFIX_ARGS = ["ssh", "-o", "BatchMode=yes", "-p", "2222", "deck@deck.invalid"]

DeckRun = Callable[[str], subprocess.CompletedProcess[str]]
SshCalls = list[tuple[list[str], dict[str, Any]]]


# @category: e2e-setup
# @dependency: full-system (Deck sshd, port 2222, BatchMode key)
@pytest.mark.skipif(
    os.environ.get("STEAMOS_MOUNTER_DECK") != "1",
    reason="on-device E2E: needs a Steam Deck; set STEAMOS_MOUNTER_DECK=1 on the host",
)
def test_deck_reachable(deck: DeckRun) -> None:
    result = deck("true")

    assert result.returncode == 0, f"ssh to the Deck failed: {result.stderr}"


# Docker-safe harness checks below.
# @category: e2e-setup  @dependency: none (subprocess.run stubbed)


@pytest.fixture
def ssh_calls(monkeypatch: pytest.MonkeyPatch) -> SshCalls:
    """Record every ``subprocess.run`` call instead of starting a process."""
    calls: SshCalls = []

    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


@pytest.mark.parametrize("deck_ssh", [FAKE_PREFIX])
@pytest.mark.parametrize("name", sorted(READ_ONLY_CHECKS))
def test_deck_runs_each_read_only_check_over_ssh(
    deck: DeckRun, ssh_calls: SshCalls, name: str
) -> None:
    command = READ_ONLY_CHECKS[name]

    deck(command)

    assert ssh_calls == [
        (
            [*FAKE_PREFIX_ARGS, command],
            {
                "stdin": subprocess.DEVNULL,
                "capture_output": True,
                "text": True,
                "check": False,
                "timeout": 60,
            },
        )
    ]


@pytest.mark.parametrize("deck_ssh", [FAKE_PREFIX])
@pytest.mark.parametrize(
    "command",
    [
        "true",
        "sudo -n ls -l /var/lib/steamos-mounter/keys",
        "sudo -n cat /etc/steamos-mounter/config.toml",
        "sudo -n stat -c '%U %G %a %n' /var/lib/steamos-mounter/keys"
        " /var/lib/steamos-mounter/keys/658207d5-5177-4a52-a297-31643c64724d.key",
    ],
)
def test_deck_runs_reachability_and_sudo_n_listings(
    deck: DeckRun, ssh_calls: SshCalls, command: str
) -> None:
    deck(command)

    assert [args for args, _ in ssh_calls] == [[*FAKE_PREFIX_ARGS, command]]


@pytest.mark.parametrize("deck_ssh", [FAKE_PREFIX])
@pytest.mark.parametrize(
    "command",
    [
        "sudo umount /run/media/deck/MEDIABOX",
        "sudo /opt/steamos-mounter/bin/steamos-mounter add --device /dev/loop0",
        "rm -rf /run/steamos-mounter",
        "systemctl --failed --no-legend; sudo reboot",
        "findmnt",
        "sudo dmsetup ls",
        "sudo -n cat /var/lib/steamos-mounter/keys/"
        "658207d5-5177-4a52-a297-31643c64724d.key",
        "",
    ],
)
def test_deck_refuses_command_outside_allow_list(
    deck: DeckRun, ssh_calls: SshCalls, command: str
) -> None:
    with pytest.raises(ValueError, match="not an allowed read-only check"):
        deck(command)

    assert ssh_calls == []


def test_deck_ssh_defaults_to_the_documented_target(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    monkeypatch.delenv("STEAMOS_MOUNTER_DECK_SSH", raising=False)

    prefix = request.getfixturevalue("deck_ssh")

    assert prefix == "ssh -o BatchMode=yes -p 2222 deck@10.0.1.100"


def test_deck_ssh_reads_the_environment(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    monkeypatch.setenv("STEAMOS_MOUNTER_DECK_SSH", FAKE_PREFIX)

    prefix = request.getfixturevalue("deck_ssh")

    assert prefix == FAKE_PREFIX


DEFAULT_PREFIX = "ssh -o BatchMode=yes -p 2222 deck@10.0.1.100"


@pytest.mark.parametrize(
    ("deck_ssh", "expected_args"),
    [
        (
            DEFAULT_PREFIX,
            ["ssh", "-o", "BatchMode=yes", "-p", "2222", "deck@10.0.1.100"],
        ),
        (
            "/usr/bin/ssh -p 2222 deck@deck.invalid",
            ["/usr/bin/ssh", "-p", "2222", "deck@deck.invalid"],
        ),
        (
            "ssh -4 -6 -q -i /home/me/.ssh/deck -l deck -F /home/me/.ssh/config"
            " -o ConnectTimeout=5 -o StrictHostKeyChecking=yes"
            " -o UserKnownHostsFile=/home/me/.ssh/known_hosts 10.0.1.100",
            [
                "ssh",
                "-4",
                "-6",
                "-q",
                "-i",
                "/home/me/.ssh/deck",
                "-l",
                "deck",
                "-F",
                "/home/me/.ssh/config",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UserKnownHostsFile=/home/me/.ssh/known_hosts",
                "10.0.1.100",
            ],
        ),
        (
            "ssh -o StrictHostKeyChecking=accept-new deck@deck.invalid",
            ["ssh", "-o", "StrictHostKeyChecking=accept-new", "deck@deck.invalid"],
        ),
        (
            "ssh -o stricthostkeychecking=Accept-New -o STRICTHOSTKEYCHECKING=YES"
            " deck@deck.invalid",
            [
                "ssh",
                "-o",
                "stricthostkeychecking=Accept-New",
                "-o",
                "STRICTHOSTKEYCHECKING=YES",
                "deck@deck.invalid",
            ],
        ),
    ],
)
def test_deck_accepts_ssh_with_allowed_options_and_one_destination(
    deck: DeckRun, ssh_calls: SshCalls, expected_args: list[str]
) -> None:
    deck("true")

    assert [args for args, _ in ssh_calls] == [[*expected_args, "true"]]


# Reason fragments of each refusal branch in conftest._ssh_prefix_args, so a
# case proves which check refused it, not only that something did.
NOT_SSH = "the program must be ssh"
NOT_ONE_DESTINATION = "exactly one destination"
OPTION_NOT_ALLOWED = "an option is outside the allow-list"
MISSING_VALUE = "an option is missing its value"
CONFIG_KEY_NOT_ALLOWED = "-o takes KEY=VALUE"
HOST_KEY_NOT_CHECKED = "StrictHostKeyChecking takes yes or accept-new only"


@pytest.mark.parametrize(
    ("deck_ssh", "reason"),
    [
        ("", NOT_SSH),
        ("   ", NOT_SSH),
        ("bash -c", NOT_SSH),
        ("sudo ssh deck@deck.invalid", NOT_SSH),
        ("./ssh deck@deck.invalid", NOT_SSH),
        ("bin/ssh deck@deck.invalid", NOT_SSH),
        ("ssh", NOT_ONE_DESTINATION),
        ("ssh -p 2222", NOT_ONE_DESTINATION),
        ("ssh deck@deck.invalid sudo", NOT_ONE_DESTINATION),
        ("ssh deck@x sudo reboot", NOT_ONE_DESTINATION),
        ("ssh deck@deck.invalid -p 2222", NOT_ONE_DESTINATION),
        ("ssh deck@deck.invalid -l deck@deck.invalid", NOT_ONE_DESTINATION),
        ("ssh -V", OPTION_NOT_ALLOWED),
        ("ssh -G deck@deck.invalid", OPTION_NOT_ALLOWED),
        ("ssh -p2222 deck@deck.invalid", OPTION_NOT_ALLOWED),
        ("ssh -oBatchMode=yes deck@deck.invalid", OPTION_NOT_ALLOWED),
        ("ssh -t deck@deck.invalid", OPTION_NOT_ALLOWED),
        ("ssh -- deck@deck.invalid", OPTION_NOT_ALLOWED),
        # A trailing command's own dash words trip the option check first.
        ("ssh deck@x sudo rm -rf /tmp/y", OPTION_NOT_ALLOWED),
        ("ssh deck@deck.invalid -o", MISSING_VALUE),
        ("ssh -i", MISSING_VALUE),
        ("ssh -o ProxyCommand=true deck@deck.invalid", CONFIG_KEY_NOT_ALLOWED),
        ("ssh -o RemoteCommand=reboot deck@deck.invalid", CONFIG_KEY_NOT_ALLOWED),
        ("ssh -o BatchMode deck@deck.invalid", CONFIG_KEY_NOT_ALLOWED),
        ("ssh -o StrictHostKeyChecking=no deck@deck.invalid", HOST_KEY_NOT_CHECKED),
        ("ssh -o stricthostkeychecking=OFF deck@deck.invalid", HOST_KEY_NOT_CHECKED),
        ("ssh -o StrictHostKeyChecking=ask deck@deck.invalid", HOST_KEY_NOT_CHECKED),
        ("ssh -o StrictHostKeyChecking= deck@deck.invalid", HOST_KEY_NOT_CHECKED),
    ],
)
def test_deck_refuses_a_prefix_outside_the_ssh_allow_list(
    deck_ssh: str,
    reason: str,
    ssh_calls: SshCalls,
    request: pytest.FixtureRequest,
) -> None:
    with pytest.raises(ValueError, match=re.escape(reason)) as refusal:
        request.getfixturevalue("deck")

    assert str(refusal.value).startswith("STEAMOS_MOUNTER_DECK_SSH is refused: ")
    assert ssh_calls == []
