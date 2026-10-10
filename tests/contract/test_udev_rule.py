"""udev rule contract.

Design Doc "udev Rule (Authoritative)", ADR-0002 D2, IP-01 and the Fact
Disposition Table row "udev properties never decide": the rule is a coarse
filter that only appends one ``SYSTEMD_WANTS`` entry. It uses only ``GOTO``,
``LABEL`` and that one assignment, and never ``RUN``, ``PROGRAM``, ``IMPORT``,
``OWNER``, ``MODE`` or ``SYMLINK``.

A small simulator runs the rule over the seven Deck property captures
(``udevadm info`` output): the BitLocker container, the ntfs partition and the
ntfs dm mapping get an auto instance; ext4 partitions, the internal NVMe and an
extended partition without a filesystem do not. The simulator supports only
what the rule needs: ``==``/``!=`` matches on ``ACTION``, ``SUBSYSTEM``,
``KERNEL`` and ``ENV{...}`` with ``|`` alternatives and shell globs, ``GOTO``,
``LABEL`` and ``ENV{...}+=``. Anything else is refused, so the simulator cannot
silently ignore a key it does not understand.
"""

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

import pytest

from tests.helpers.fixtures import load_fixture

REPO = Path(__file__).resolve().parents[2]
RULE_FILE = REPO / "data" / "90-steamos-mounter.rules"

AUTO_TEMPLATE = "steamos-mounter-auto@.service"
WANTS = "SYSTEMD_WANTS"
FORBIDDEN_KEYS = ("RUN", "PROGRAM", "IMPORT", "OWNER", "MODE", "SYMLINK")
MATCH_KEYS = frozenset({"ACTION", "SUBSYSTEM", "KERNEL", "ENV"})
MATCH_OPERATORS = frozenset({"==", "!="})
END_LABEL = "steamos_mounter_end"
# KEY or KEY{attr}, an operator, a double-quoted value, then a comma or the end.
TOKEN = re.compile(
    r"\s*(?P<key>[A-Z_]+)(?:\{(?P<attr>[^}]+)\})?\s*"
    r'(?P<op>==|!=|\+=|-=|:=|=)\s*"(?P<value>[^"]*)"\s*(?:,|$)'
)


@dataclass(frozen=True, slots=True)
class Token:
    key: str
    attr: str | None
    op: str
    value: str


@dataclass(frozen=True, slots=True)
class Event:
    action: str
    properties: dict[str, str]


def parse_rule_line(line: str) -> tuple[Token, ...]:
    """The comma-separated ``KEY[{attr}]OP"value"`` tokens of one rule line.

    Raises ``ValueError`` when any part of the line is not a token.
    """
    tokens: list[Token] = []
    position = 0
    while position < len(line):
        match = TOKEN.match(line, position)
        if match is None or match.end() == position:
            raise ValueError(f"cannot read rule text at {line[position:]!r}")
        tokens.append(Token(match["key"], match["attr"], match["op"], match["value"]))
        position = match.end()
    return tuple(tokens)


def rule_lines(text: str) -> list[tuple[Token, ...]]:
    """Every non-comment, non-blank line of ``text`` as its tokens."""
    return [
        parse_rule_line(line)
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def parse_properties(capture: str) -> dict[str, str]:
    """``KEY=VALUE`` lines of a ``udevadm info --query=property`` capture."""
    properties: dict[str, str] = {}
    for line in capture.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key] = value
    return properties


def _field(token: Token, event: Event) -> str:
    """The event value a match key reads; a missing property reads as empty."""
    if token.key == "ACTION":
        return event.action
    if token.key == "KERNEL":
        return PurePosixPath(event.properties.get("DEVNAME", "")).name
    if token.key == "ENV":
        return event.properties.get(token.attr or "", "")
    return event.properties.get(token.key, "")


def _matches(token: Token, event: Event) -> bool:
    hit = any(
        fnmatchcase(_field(token, event), pattern) for pattern in token.value.split("|")
    )
    return hit if token.op == "==" else not hit


def _label(tokens: tuple[Token, ...]) -> str | None:
    labels = [token.value for token in tokens if token.key == "LABEL"]
    return labels[0] if labels else None


def _all_match(tokens: tuple[Token, ...], event: Event) -> bool:
    matchers = [token for token in tokens if token.op in MATCH_OPERATORS]
    unknown = [token.key for token in matchers if token.key not in MATCH_KEYS]
    if unknown:
        raise ValueError(f"simulator does not model match key {unknown[0]}")
    return all(_matches(token, event) for token in matchers)


def _apply(tokens: tuple[Token, ...], wants: list[str]) -> str | None:
    """Run the assignments of a matching line; returns its ``GOTO`` label."""
    goto: str | None = None
    for token in tokens:
        if token.op in MATCH_OPERATORS:
            continue
        if token.key == "GOTO" and token.op == "=":
            goto = token.value
        elif token.key == "ENV" and token.attr == WANTS and token.op == "+=":
            wants.extend(token.value.split())
        else:
            raise ValueError(f"simulator does not model {token.key}{token.op}")
    return goto


def simulate(text: str, event: Event) -> list[str]:
    """The ``SYSTEMD_WANTS`` entries the rule text appends for ``event``.

    Raises ``ValueError`` for a key or operator the simulator does not model.
    """
    wants: list[str] = []
    goto: str | None = None
    for tokens in rule_lines(text):
        label = _label(tokens)
        if goto is not None:
            goto = None if label == goto else goto
        elif label is None and _all_match(tokens, event):
            goto = _apply(tokens, wants)
    return wants


def rule_text() -> str:
    return RULE_FILE.read_text(encoding="utf-8")


def all_tokens() -> list[Token]:
    return [token for tokens in rule_lines(rule_text()) for token in tokens]


def capture_event(name: str, action: str = "add") -> Event:
    return Event(action, parse_properties(load_fixture(name).decode("utf-8")))


# --- the simulator itself -------------------------------------------------------------


def test_tokenizer_reads_keys_attributes_operators_and_values():
    assert parse_rule_line('KERNEL!="sd*|dm-*", ENV{X}+="a b"') == (
        Token("KERNEL", None, "!=", "sd*|dm-*"),
        Token("ENV", "X", "+=", "a b"),
    )


def test_tokenizer_refuses_text_it_cannot_read():
    with pytest.raises(ValueError, match="cannot read rule text"):
        parse_rule_line('KERNEL=="sd*" garbage')


def test_simulator_refuses_a_key_it_does_not_model():
    event = Event("add", {"DEVNAME": "/dev/sdb5"})

    with pytest.raises(ValueError, match="does not model RUN"):
        simulate('KERNEL=="sd*", RUN+="/bin/true"\n', event)


def test_simulator_refuses_a_match_key_it_does_not_model():
    event = Event("add", {"DEVNAME": "/dev/sdb5"})

    with pytest.raises(ValueError, match="match key ATTR"):
        simulate('ATTR=="x", ENV{SYSTEMD_WANTS}+="a"\n', event)


def test_simulator_goto_skips_to_its_label():
    text = 'KERNEL=="sd*", GOTO="end"\nENV{SYSTEMD_WANTS}+="a"\nLABEL="end"\n'
    text += 'ENV{SYSTEMD_WANTS}+="b"\n'

    assert simulate(text, Event("add", {"DEVNAME": "/dev/sda"})) == ["b"]
    assert simulate(text, Event("add", {"DEVNAME": "/dev/vda"})) == ["a", "b"]


def test_capture_parser_splits_at_the_first_equals_sign():
    assert parse_properties("A=1\nB=x=y\nnot a property\n") == {"A": "1", "B": "x=y"}


# --- rule shape (IP-01, ADR-0002 D2) --------------------------------------------------


def test_rule_assigns_only_goto_label_and_one_systemd_wants():
    assignments = [token for token in all_tokens() if token.op not in MATCH_OPERATORS]
    wants = [token for token in assignments if token.key == "ENV"]

    assert {token.key for token in assignments} == {"GOTO", "LABEL", "ENV"}
    assert wants == [Token("ENV", WANTS, "+=", AUTO_TEMPLATE)]


def test_rule_matches_only_on_action_subsystem_kernel_and_env():
    matchers = {token.key for token in all_tokens() if token.op in MATCH_OPERATORS}

    assert matchers <= MATCH_KEYS


@pytest.mark.parametrize("key", FORBIDDEN_KEYS)
def test_rule_never_uses_a_forbidden_key(key):
    assert key not in {token.key for token in all_tokens()}
    assert not re.search(rf"(?m)(^|[\s,]){key}\b", rule_text())


def test_every_goto_has_its_label():
    tokens = all_tokens()
    gotos = {token.value for token in tokens if token.key == "GOTO"}
    labels = {token.value for token in tokens if token.key == "LABEL"}

    assert gotos == labels == {END_LABEL}


# --- rule simulation over the Deck captures -------------------------------------------


@pytest.mark.parametrize(
    "capture",
    ["udev-sdb1.txt", "udev-sdb5.txt", "udev-dm-0.txt"],
    ids=["bitlocker-sdb1", "ntfs-sdb5", "ntfs-mapping-dm-0"],
)
@pytest.mark.parametrize("action", ["add", "change"])
def test_bitlocker_ntfs_and_the_dm_mapping_get_an_auto_instance(capture, action):
    assert simulate(rule_text(), capture_event(capture, action)) == [AUTO_TEMPLATE]


@pytest.mark.parametrize(
    "capture",
    ["udev-sda1.txt", "udev-mmcblk0p1.txt", "udev-nvme0n1p8.txt", "udev-sdb2.txt"],
    ids=["ext4-sda1", "ext4-mmcblk0p1", "nvme-home", "extended-sdb2"],
)
def test_ext4_nvme_and_no_filesystem_get_nothing(capture):
    assert simulate(rule_text(), capture_event(capture)) == []


def test_remove_event_gets_nothing():
    assert simulate(rule_text(), capture_event("udev-sdb5.txt", "remove")) == []


@pytest.mark.parametrize(
    ("devname", "fstype"),
    [
        ("/dev/nvme0n1p9", "ntfs"),
        ("/dev/loop0", "exfat"),
        ("/dev/zram0", "vfat"),
        ("/dev/sdc1", "bitlocker"),
    ],
)
def test_other_kernels_and_the_wrong_case_get_nothing(devname, fstype):
    event = Event(
        "add", {"DEVNAME": devname, "SUBSYSTEM": "block", "ID_FS_TYPE": fstype}
    )

    assert simulate(rule_text(), event) == []


@pytest.mark.parametrize("fstype", ["ntfs", "exfat", "vfat", "btrfs", "BitLocker"])
def test_every_supported_type_on_a_removable_kernel_gets_an_auto_instance(fstype):
    event = Event(
        "add", {"DEVNAME": "/dev/mmcblk0p1", "SUBSYSTEM": "block", "ID_FS_TYPE": fstype}
    )

    assert simulate(rule_text(), event) == [AUTO_TEMPLATE]


def test_non_block_subsystem_gets_nothing():
    event = Event(
        "add", {"DEVNAME": "/dev/sdb5", "SUBSYSTEM": "net", "ID_FS_TYPE": "ntfs"}
    )

    assert simulate(rule_text(), event) == []
