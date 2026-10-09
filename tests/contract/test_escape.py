"""systemd path escaping conformance (Fact "systemd-escape:instance-naming").

Design Doc: docs/design/steamos-mounter-design.md (sections "blockdev, mounts,
naming, escape" and the Fact Disposition Table row
"systemd-escape:instance-naming"); ADR-0002 D1 (instance names come from the
by-uuid path or the sysfs path, never from labels, and must fit systemd's
unit-name limit).

Every row of ``fixtures/deck/systemd-escape.tsv`` is real ``systemd-escape``
output from the Deck. A mismatch would make the tool talk to a different unit
than the one udev started, so each row must be reproduced exactly.

The edge cases below the TSV (root, double slashes, a leading dot, non-ASCII,
characters outside systemd's valid set, the 255/256 boundary) were checked
against ``systemd-escape`` 249 on the development host: ``--path`` and
``--unescape --path`` for the rows, and ``--template=x@.service`` for the
length boundary (a 255-character name is accepted, 256 is refused with
"Invalid argument"). systemd's own check is ``strlen(name) >= UNIT_NAME_MAX``
with ``UNIT_NAME_MAX`` 256.
"""

import csv
import io

import pytest

from steamos_mounter.escape import (
    UNIT_NAME_MAX,
    auto_instance,
    escape_path,
    registered_instance,
    unescape_path,
    unit_name,
)
from tests.helpers.fixtures import load_fixture

TSV = "systemd-escape.tsv"
REGISTERED_TEMPLATE = "steamos-mounter@"
AUTO_TEMPLATE = "steamos-mounter-auto@"
BY_UUID = "/dev/disk/by-uuid/"
SERVICE = ".service"
ROW_KINDS = frozenset(
    {"path", "template-registered", "template-auto", "unescape-path", "instance-length"}
)


def tsv_rows() -> list[dict[str, str]]:
    text = load_fixture(TSV).decode("utf-8")
    reader = csv.DictReader(io.StringIO(text), delimiter="\t", quoting=csv.QUOTE_NONE)
    return list(reader)


def rows_of(kind: str) -> list[tuple[str, str]]:
    return [(row["input"], row["output"]) for row in tsv_rows() if row["kind"] == kind]


def test_tsv_holds_only_known_row_kinds():
    # A new kind of row must get a test here, not be skipped silently.
    kinds = {row["kind"] for row in tsv_rows()}

    assert kinds == ROW_KINDS


def test_tsv_row_counts_per_kind():
    counts = {kind: len(rows_of(kind)) for kind in ROW_KINDS}

    assert counts == {
        "path": 7,
        "template-registered": 2,
        "template-auto": 4,
        "unescape-path": 4,
        "instance-length": 4,
    }


@pytest.mark.parametrize(("path", "expected"), rows_of("path"))
def test_escape_path_equals_systemd_escape(path: str, expected: str):
    assert escape_path(path) == expected


@pytest.mark.parametrize(("path", "expected"), rows_of("template-registered"))
def test_registered_unit_name_equals_systemd_escape(path: str, expected: str):
    uuid = path.removeprefix(BY_UUID)

    assert unit_name(REGISTERED_TEMPLATE, registered_instance(uuid)) == expected


@pytest.mark.parametrize(("syspath", "expected"), rows_of("template-auto"))
def test_auto_unit_name_equals_systemd_escape(syspath: str, expected: str):
    assert unit_name(AUTO_TEMPLATE, auto_instance(syspath)) == expected


@pytest.mark.parametrize(("escaped", "expected"), rows_of("unescape-path"))
def test_unescape_path_equals_systemd_escape(escaped: str, expected: str):
    assert unescape_path(escaped) == expected


@pytest.mark.parametrize(("instance", "length"), rows_of("instance-length"))
def test_instance_length_matches_capture(instance: str, length: str):
    assert len(escape_path(unescape_path(instance))) == int(length)


@pytest.mark.parametrize(("path", "expected"), rows_of("path"))
def test_unescape_inverts_every_captured_escape(path: str, expected: str):
    assert unescape_path(expected) == path


# Checked with systemd-escape 249 on the development host (module docstring).
HOST_ESCAPE_CASES = (
    ("/", "-"),
    ("//a//b/", "a-b"),
    ("/a/./b", "a-b"),
    ("/.dotdir", r"\x2edotdir"),
    ("/a/.b", "a-.b"),
    ("/run/media/deck/MÉDIA", r"run-media-deck-M\xc3\x89DIA"),
    ("/a b\\c", r"a\x20b\x5cc"),
    ("/x-y_z:1.2", r"x\x2dy_z:1.2"),
    ("/~+@%", r"\x7e\x2b\x40\x25"),
)


@pytest.mark.parametrize(("path", "expected"), HOST_ESCAPE_CASES)
def test_escape_path_edge_cases(path: str, expected: str):
    assert escape_path(path) == expected


HOST_UNESCAPE_CASES = (
    ("-", "/"),
    (r"a\x2db-c", "/a-b/c"),
    (r"a\x2Db", "/a-b"),
    (r"a\x2fb", "/a/b"),
    (r"\x2edot", "/.dot"),
    (r"r\xc3\x89", "/rÉ"),
)


@pytest.mark.parametrize(("escaped", "expected"), HOST_UNESCAPE_CASES)
def test_unescape_path_edge_cases(escaped: str, expected: str):
    assert unescape_path(escaped) == expected


def test_undecodable_bytes_round_trip():
    # A sysfs path is bytes; undecodable ones travel as lone surrogates (DD-01).
    path = b"/sys/block/x\xff".decode("utf-8", "surrogateescape")

    escaped = escape_path(path)

    assert escaped == r"sys-block-x\xff"
    assert unescape_path(escaped) == path


@pytest.mark.parametrize(
    "path",
    [
        "/a/../b",  # systemd: "Failed to escape string: Invalid argument"
        "/..",
        "relative/path",  # stricter than systemd: instances come from absolute paths
        "",
        "/a\x00b",  # systemd would truncate at NUL; refused instead
    ],
)
def test_escape_path_refuses_unsafe_paths(path: str):
    with pytest.raises(ValueError, match="cannot escape path"):
        escape_path(path)


@pytest.mark.parametrize(
    "escaped",
    [
        "",
        r"a\x",  # systemd: "Failed to unescape string: Invalid argument"
        r"a\q",
        r"a\xzzb",
        "-a",
        "a-",
        "a--b",
        "a-.-b",
        "a-..-b",
        r"a\x2f",
        r"\x2fa",
        r"a\x00b",  # systemd would truncate at NUL; refused instead
    ],
)
def test_unescape_path_refuses_invalid_names(escaped: str):
    with pytest.raises(ValueError, match="cannot unescape"):
        unescape_path(escaped)


@pytest.mark.parametrize("uuid", ["", ".", "..", "a/b", "../../sda1"])
def test_registered_instance_refuses_uuid_that_is_not_one_component(uuid: str):
    with pytest.raises(ValueError, match="not a single path component"):
        registered_instance(uuid)


def test_unit_name_limit_constant_is_systemds():
    assert UNIT_NAME_MAX == 256


def test_unit_name_of_255_characters_is_accepted():
    instance = "a" * (255 - len(AUTO_TEMPLATE) - len(SERVICE))

    name = unit_name(AUTO_TEMPLATE, instance)

    assert len(name) == 255


def test_unit_name_of_256_characters_raises():
    instance = "a" * (256 - len(AUTO_TEMPLATE) - len(SERVICE))

    with pytest.raises(ValueError, match="256"):
        unit_name(AUTO_TEMPLATE, instance)


def test_unit_name_far_over_the_limit_raises():
    with pytest.raises(ValueError, match="256"):
        unit_name(AUTO_TEMPLATE, "a" * 1000)


def test_longest_captured_auto_unit_name_fits():
    longest = max(len(expected) for _, expected in rows_of("template-auto"))

    assert longest < UNIT_NAME_MAX


@pytest.mark.parametrize(
    "template", ["steamos-mounter", "steamos-mounter@.service", ""]
)
def test_unit_name_refuses_template_without_trailing_at(template: str):
    with pytest.raises(ValueError, match="template"):
        unit_name(template, "dev-sdb1")


def test_unit_name_refuses_empty_instance():
    with pytest.raises(ValueError, match="instance"):
        unit_name(AUTO_TEMPLATE, "")
