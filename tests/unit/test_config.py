"""The registry: validation on every read, the emitter and the locked write.

Design Doc "Registry (config.toml)" (Schema, Validation on Every Read, Emitter,
Atomic Write), "Data Contracts > config.load" and DD-07; ADR-0004 D3; PRD
AC-005 (no key field), I001 (an absent file is an empty registry) and NFR-25
(no volume-count limit). Owner decision 4: ``save`` only writes; its callers
wire. Files are real files under ``tmp_path`` owned by the test uid, which is
the ``FakePlatform``'s ``trusted_uid``.
"""

import dataclasses
import os
import stat
import threading
import time
import tomllib
import traceback
from pathlib import Path

import pytest

from steamos_mounter import config
from steamos_mounter.config import emit, load, parse, save, with_volume, without_volume
from steamos_mounter.errors import ExitCode, RefusedError, RegistryError, UsageError
from steamos_mounter.locks import registry_lock
from steamos_mounter.model import Driver, InvalidEntry, Mode, Registry, Step, Volume
from steamos_mounter.platforms import steamos
from tests.helpers import builders
from tests.helpers.builders import (
    MEDIABOX,
    PERSONAL,
    raw_registry_text,
    raw_volume_table,
    registry_text,
    volume_fields,
)

MOUNT_BASE = "/run/media/deck"
NOT_BASE_CHILD = "path must be directly under the mount base"
ETC = "etc/steamos-mounter"
LOCKS = "run/steamos-mounter/locks"
HEADER = (
    "# steamos-mounter registry. Managed by steamos-mounter: "
    "comments and formatting are not kept.\n"
)
# The Design Doc "Schema (Version 1)" example, byte for byte.
DESIGN_EXAMPLE = (
    HEADER
    + """\
schema_version = 1

[[volume]]
name = "MEDIABOX"
uuid = "01D95F1575592A30"
path = "/run/media/deck/MEDIABOX"
fstype = "ntfs"
nosuid = true
nodev = true

[[volume]]
name = "PERSONAL"
uuid = "658207d5-5177-4a52-a297-31643c64724d"
path = "/run/media/deck/PERSONAL"
fstype = "BitLocker"
drivers = ["ntfs3", "ntfs-3g", "ntfs3:ro"]
nosuid = true
nodev = true
"""
)
EMPTY_TEXT = HEADER + "schema_version = 1\n"

MEDIABOX_VOLUME = Volume(
    name="MEDIABOX",
    uuid="01D95F1575592A30",
    path="/run/media/deck/MEDIABOX",
    fstype="ntfs",
    drivers=None,
    nosuid=True,
    nodev=True,
)
PERSONAL_VOLUME = Volume(
    name="PERSONAL",
    uuid="658207d5-5177-4a52-a297-31643c64724d",
    path="/run/media/deck/PERSONAL",
    fstype="BitLocker",
    drivers=(
        Step(Driver.NTFS3, Mode.RW),
        Step(Driver.NTFS3G, Mode.RW),
        Step(Driver.NTFS3, Mode.RO),
    ),
    nosuid=True,
    nodev=True,
)
EMPTY = Registry(schema_version=1, volumes=(), invalid=())
TEST_KEY = "TEST-KEY-7f3a9c-do-not-leak"


def _one_entry(**changes: object) -> str:
    """Registry text with one MEDIABOX entry; ``None`` drops a key."""
    fields = volume_fields(MEDIABOX) | changes
    kept = {key: value for key, value in fields.items() if value is not None}
    return raw_registry_text([raw_volume_table(kept)])


def _parse_one(**changes: object) -> Registry:
    return parse(_one_entry(**changes), mount_base=MOUNT_BASE)


@pytest.fixture
def etc_dir(tmp_path: Path) -> Path:
    directory = tmp_path / ETC
    directory.mkdir(parents=True)
    directory.chmod(0o755)
    return directory


@pytest.fixture
def locks_dir(tmp_path: Path) -> Path:
    directory = tmp_path / LOCKS
    directory.mkdir(parents=True)
    directory.chmod(0o700)
    return directory


def _write_registry(etc_dir: Path, text: str, mode: int = 0o644) -> Path:
    path = etc_dir / "config.toml"
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


# --- parse: the good path -------------------------------------------------------------


def test_parse_reads_the_design_doc_example():
    assert parse(DESIGN_EXAMPLE, mount_base=MOUNT_BASE) == Registry(
        schema_version=1, volumes=(MEDIABOX_VOLUME, PERSONAL_VOLUME), invalid=()
    )


def test_parse_without_volumes_is_the_empty_registry():
    assert parse(EMPTY_TEXT) == EMPTY


def test_parse_keeps_file_order():
    text = raw_registry_text(
        [
            raw_volume_table(volume_fields(PERSONAL)),
            raw_volume_table(volume_fields(MEDIABOX)),
        ]
    )

    names = [volume.name for volume in parse(text, mount_base=MOUNT_BASE).volumes]

    assert names == ["PERSONAL", "MEDIABOX"]


def test_nosuid_and_nodev_default_to_true():
    registry = _parse_one(nosuid=None, nodev=None)

    assert registry.volumes == (MEDIABOX_VOLUME,)


def test_nosuid_and_nodev_false_is_the_explicit_opt_out():
    (volume,) = _parse_one(nosuid=False, nodev=False).volumes

    assert (volume.nosuid, volume.nodev) == (False, False)


@pytest.mark.parametrize(
    ("tokens", "steps"),
    [
        (["ntfs3"], (Step(Driver.NTFS3, Mode.RW),)),
        (["ntfs3:ro"], (Step(Driver.NTFS3, Mode.RO),)),
        (["ntfs-3g"], (Step(Driver.NTFS3G, Mode.RW),)),
        (["ntfs-3g:ro"], (Step(Driver.NTFS3G, Mode.RO),)),
        (["ntfs"], (Step(Driver.NTFS, Mode.RW),)),
        (["ntfs:ro"], (Step(Driver.NTFS, Mode.RO),)),
        (
            ["ntfs:ro", "ntfs3", "ntfs3:ro"],
            (
                Step(Driver.NTFS, Mode.RO),
                Step(Driver.NTFS3, Mode.RW),
                Step(Driver.NTFS3, Mode.RO),
            ),
        ),
    ],
)
def test_drivers_tokens_become_steps_in_order(tokens, steps):
    (volume,) = _parse_one(drivers=tokens).volumes

    assert volume.drivers == steps


@pytest.mark.parametrize("fstype", ["ntfs", "BitLocker"])
def test_drivers_allowed_for_ntfs_and_bitlocker(fstype):
    registry = _parse_one(fstype=fstype, drivers=["ntfs-3g"])

    assert registry.invalid == ()


# --- parse: an unusable file ----------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        (HEADER + "schema_version = 1\n[[volume]\n", "not valid TOML"),
        (HEADER + "schema_version = 1\nschema_version = 1\n", "not valid TOML"),
        (
            raw_registry_text([], top="schema_version = 1\nlabel = 'x'"),
            "unknown top-level key 'label'",
        ),
        (
            raw_registry_text([], top="schema_version = 1\nkey = 'x'"),
            "unknown top-level key 'key'",
        ),
        (raw_registry_text([], top="schema_version = 2"), "schema_version is not 1"),
        (raw_registry_text([], top="schema_version = 0"), "schema_version is not 1"),
        (raw_registry_text([], top="schema_version = '1'"), "schema_version is not 1"),
        (raw_registry_text([], top="schema_version = true"), "schema_version is not 1"),
        (raw_registry_text([], top="schema_version = 1.0"), "schema_version is not 1"),
        (HEADER, "schema_version is missing"),
        (raw_registry_text([], top="volume = []"), "schema_version is missing"),
        (
            raw_registry_text([], top="schema_version = 1\nvolume = 'x'"),
            "volume is not an array of tables",
        ),
        (
            raw_registry_text([], top="schema_version = 1\n[volume]\nname = 'x'"),
            "volume is not an array of tables",
        ),
    ],
)
def test_unusable_file_raises_registry_error(text, reason):
    with pytest.raises(RegistryError) as raised:
        parse(text)

    assert raised.value.detail.startswith(reason)
    assert str(raised.value) == "the registry cannot be used"


RECOVERY_KEY = "123456-234567-345678-456789-567890-678901-789012-890123"
# Ways a key pasted into config.toml makes the file unusable: as a top-level
# key name, and as a key name tomllib quotes in its own error text.
UNUSABLE_WITH_PASTED_KEY = (
    raw_registry_text([], top=f"schema_version = 1\n{RECOVERY_KEY} = true"),
    raw_registry_text(
        [], top=f"schema_version = 1\n[{RECOVERY_KEY}]\n[{RECOVERY_KEY}]"
    ),
    raw_registry_text(
        [], top=f"schema_version = 1\nx = {{{RECOVERY_KEY} = 1, {RECOVERY_KEY} = 2}}"
    ),
)
PASTED_IDS = ["top-level-key", "table-declared-twice", "inline-duplicate"]


@pytest.mark.parametrize("text", UNUSABLE_WITH_PASTED_KEY, ids=PASTED_IDS)
def test_an_unusable_file_never_carries_a_pasted_key(text):
    with pytest.raises(RegistryError) as raised:
        parse(text)

    error = raised.value
    told = "".join(traceback.format_exception(error)) + error.detail + repr(error)
    carried = RECOVERY_KEY in told
    assert not carried


def test_invalid_toml_without_a_position_says_only_that(monkeypatch):
    """A tomllib message without its usual position suffix: nothing of it is kept."""

    class Unplaced(tomllib.TOMLDecodeError):
        pass

    def unplaced(_text: str) -> dict[str, object]:
        # __new__ alone: no position suffix, and no 3.14 constructor warning.
        raise Unplaced.__new__(Unplaced, f"Duplicate key {RECOVERY_KEY!r}")

    monkeypatch.setattr(config.tomllib, "loads", unplaced)

    with pytest.raises(RegistryError) as raised:
        parse("ignored")

    assert raised.value.detail == "not valid TOML"


def test_a_pasted_top_level_key_is_reported_unnamed():
    with pytest.raises(RegistryError) as raised:
        parse(UNUSABLE_WITH_PASTED_KEY[0])

    assert raised.value.detail == "unknown top-level key"


def test_an_identifier_like_top_level_key_is_named():
    with pytest.raises(RegistryError) as raised:
        parse(raw_registry_text([], top="schema_version = 1\nvolumes = []"))

    assert raised.value.detail == "unknown top-level key 'volumes'"


@pytest.mark.parametrize(
    ("text", "detail"),
    [
        (HEADER + "schema_version = [\n", "not valid TOML (at end of document)"),
        (
            UNUSABLE_WITH_PASTED_KEY[1],
            "not valid TOML (at line 4, column 57)",
        ),
    ],
    ids=["end-of-document", "line-and-column"],
)
def test_invalid_toml_keeps_only_the_position(text, detail):
    with pytest.raises(RegistryError) as raised:
        parse(text)

    error = raised.value
    assert error.detail == detail
    assert error.__cause__ is None
    assert error.__context__ is None


def test_empty_volume_array_is_no_registrations():
    assert parse(raw_registry_text([], top="schema_version = 1\nvolume = []")) == EMPTY


# --- parse: per-entry rules (table-driven) --------------------------------------------

VALID_ROWS = [
    pytest.param({"name": "A"}, id="name-one-character"),
    pytest.param({"name": "A" * 64}, id="name-64-characters"),
    pytest.param({"name": "9.drive_x-y"}, id="name-digits-dot-underscore-dash"),
    pytest.param({"uuid": "C40C-B21F"}, id="uuid-fat-upper"),
    pytest.param({"uuid": "c40c-b21f"}, id="uuid-fat-lower"),
    pytest.param({"uuid": "01d95f1575592a30"}, id="uuid-ntfs-lower"),
    pytest.param(
        {"uuid": "658207D5-5177-4A52-A297-31643C64724D"}, id="uuid-rfc4122-upper"
    ),
    pytest.param({"path": "/run/media/deck/media box"}, id="path-with-space"),
    pytest.param({"path": "/run/media/deck/A+B"}, id="path-with-plus"),
    pytest.param({"path": "/run/media/deck/OTHER"}, id="path-leaf-not-the-name"),
    pytest.param({"fstype": "exfat"}, id="fstype-exfat"),
    pytest.param({"fstype": "vfat"}, id="fstype-vfat"),
    pytest.param({"fstype": "btrfs"}, id="fstype-btrfs"),
]


@pytest.mark.parametrize("changes", VALID_ROWS)
def test_entry_rule_accepts(changes):
    registry = _parse_one(**changes)

    assert registry.invalid == ()
    assert len(registry.volumes) == 1


INVALID_ROWS = [
    # name
    pytest.param({"name": None}, "missing key 'name'", id="name-missing"),
    pytest.param({"name": 5}, "name: must be a string", id="name-integer"),
    pytest.param({"name": ""}, "name: not a valid registry name", id="name-empty"),
    pytest.param({"name": "A" * 65}, "name: not a valid registry name", id="name-65"),
    pytest.param(
        {"name": "-A"}, "name: not a valid registry name", id="name-leading-dash"
    ),
    pytest.param(
        {"name": ".A"}, "name: not a valid registry name", id="name-leading-dot"
    ),
    pytest.param({"name": "A B"}, "name: not a valid registry name", id="name-space"),
    pytest.param({"name": "A/B"}, "name: not a valid registry name", id="name-slash"),
    pytest.param(
        {"name": "MÉDIA"}, "name: not a valid registry name", id="name-non-ascii"
    ),
    pytest.param({"name": "A\n"}, "name: not a valid registry name", id="name-newline"),
    # uuid
    pytest.param({"uuid": None}, "missing key 'uuid'", id="uuid-missing"),
    pytest.param({"uuid": 1234}, "uuid: must be a string", id="uuid-integer"),
    pytest.param({"uuid": "C40CB21F"}, "uuid: not a valid UUID", id="uuid-fat-no-dash"),
    pytest.param({"uuid": "C40C-B21"}, "uuid: not a valid UUID", id="uuid-fat-short"),
    pytest.param({"uuid": "G40C-B21F"}, "uuid: not a valid UUID", id="uuid-not-hex"),
    pytest.param(
        {"uuid": "01D95F1575592A3"}, "uuid: not a valid UUID", id="uuid-ntfs-15"
    ),
    pytest.param(
        {"uuid": "01D95F1575592A300"}, "uuid: not a valid UUID", id="uuid-ntfs-17"
    ),
    pytest.param(
        {"uuid": "01D95F1575592A30\n"}, "uuid: not a valid UUID", id="uuid-newline"
    ),
    pytest.param(
        {"uuid": "658207d551774a52a29731643c64724d"},
        "uuid: not a valid UUID",
        id="uuid-rfc-no-dash",
    ),
    pytest.param(
        {"uuid": "658207d5-5177-4a52-a297-31643c64724"},
        "uuid: not a valid UUID",
        id="uuid-rfc-short",
    ),
    pytest.param({"uuid": "../../etc"}, "uuid: not a valid UUID", id="uuid-traversal"),
    # path
    pytest.param({"path": None}, "missing key 'path'", id="path-missing"),
    pytest.param(
        {"path": ["/run/media/deck/a"]}, "path: must be a string", id="path-list"
    ),
    pytest.param(
        {"path": "run/media/deck/A"}, "path must be absolute", id="path-relative"
    ),
    pytest.param(
        {"path": "/run/media/deck/a/"},
        "path must not end with /",
        id="path-trailing-slash",
    ),
    pytest.param(
        {"path": "/run/media/deck/../etc"},
        "path must not contain . or .. components",
        id="path-dotdot",
    ),
    pytest.param(
        {"path": "/run/media/deck/a\tb"},
        "path contains a control character",
        id="path-control",
    ),
    pytest.param(
        {"path": "/home/deck"}, "path is a protected directory", id="path-protected"
    ),
    pytest.param(
        {"path": "/etc/x"}, "path is at or under a system directory", id="path-system"
    ),
    pytest.param(
        {"path": "/run/x"}, "path is under /run but not under /run/media", id="path-run"
    ),
    pytest.param(
        {"path": "/run/media"},
        "path is the mount base or one of its parents",
        id="path-run-media",
    ),
    pytest.param(
        {"path": MOUNT_BASE},
        "path is the mount base or one of its parents",
        id="path-mount-base",
    ),
    # rule 9 (DD-34): only direct children of the mount base
    pytest.param({"path": "/mnt/media box"}, NOT_BASE_CHILD, id="path-mnt"),
    pytest.param(
        {"path": "/home/deck/Drives/A+B"}, NOT_BASE_CHILD, id="path-under-home-deck"
    ),
    pytest.param(
        {"path": "/run/media/deck/STICK/sub/A"},
        NOT_BASE_CHILD,
        id="path-under-a-mounted-stick",
    ),
    pytest.param(
        {"path": "/run/media/other"}, NOT_BASE_CHILD, id="path-sibling-of-the-base"
    ),
    # fstype (DD-07)
    pytest.param({"fstype": None}, "missing key 'fstype'", id="fstype-missing"),
    pytest.param({"fstype": True}, "fstype: must be a string", id="fstype-boolean"),
    pytest.param(
        {"fstype": "ext4"}, "fstype: not a supported filesystem type", id="fstype-ext4"
    ),
    pytest.param(
        {"fstype": "ntfs3"},
        "fstype: not a supported filesystem type",
        id="fstype-driver-name",
    ),
    pytest.param(
        {"fstype": "bitlocker"},
        "fstype: not a supported filesystem type",
        id="fstype-case",
    ),
    pytest.param(
        {"fstype": "NTFS"}, "fstype: not a supported filesystem type", id="fstype-upper"
    ),
    # drivers
    pytest.param(
        {"drivers": "ntfs3"}, "drivers: must be a list of strings", id="drivers-string"
    ),
    pytest.param(
        {"drivers": [1]},
        "drivers: must be a list of strings",
        id="drivers-integer-item",
    ),
    pytest.param({"drivers": []}, "drivers: must not be empty", id="drivers-empty"),
    pytest.param(
        {"drivers": ["ntfs4"]}, "drivers: unknown token", id="drivers-unknown"
    ),
    pytest.param(
        {"drivers": ["ntfs3:rw"]}, "drivers: unknown token", id="drivers-rw-suffix"
    ),
    pytest.param({"drivers": ["NTFS3"]}, "drivers: unknown token", id="drivers-case"),
    pytest.param(
        {"drivers": ["exfat"]}, "drivers: unknown token", id="drivers-other-fs"
    ),
    pytest.param(
        {"drivers": ["ntfs3", "ntfs3"]},
        "drivers: duplicate token",
        id="drivers-duplicate",
    ),
    pytest.param(
        {"fstype": "exfat", "drivers": ["ntfs3"]},
        "drivers: only for ntfs or BitLocker",
        id="drivers-exfat",
    ),
    pytest.param(
        {"fstype": "btrfs", "drivers": ["ntfs3"]},
        "drivers: only for ntfs or BitLocker",
        id="drivers-btrfs",
    ),
    # nosuid, nodev
    pytest.param({"nosuid": "true"}, "nosuid: must be a boolean", id="nosuid-string"),
    pytest.param({"nosuid": 1}, "nosuid: must be a boolean", id="nosuid-integer"),
    pytest.param({"nodev": "false"}, "nodev: must be a boolean", id="nodev-string"),
    # unknown keys (AC-005 and the closed schema)
    pytest.param({"label": "MEDIABOX"}, "unknown key 'label'", id="unknown-label"),
    pytest.param({"options": "rw"}, "unknown key 'options'", id="unknown-options"),
]


@pytest.mark.parametrize(("changes", "reason"), INVALID_ROWS)
def test_entry_rule_refuses(changes, reason):
    registry = _parse_one(**changes)

    assert registry.volumes == ()
    assert len(registry.invalid) == 1
    assert registry.invalid[0].index == 0
    assert registry.invalid[0].reason == reason


def test_invalid_entry_keeps_its_uuid_when_the_uuid_is_valid():
    registry = _parse_one(fstype="ext4")

    assert registry.invalid == (
        InvalidEntry(
            index=0,
            uuid="01D95F1575592A30",
            reason="fstype: not a supported filesystem type",
        ),
    )


def test_invalid_entry_has_no_uuid_when_the_uuid_is_invalid():
    registry = _parse_one(uuid="not-a-uuid")

    assert registry.invalid[0].uuid is None


def test_entry_that_is_not_a_table_is_invalid():
    text = raw_registry_text([], top="schema_version = 1\nvolume = [1, 'x']")

    registry = parse(text)

    assert registry.invalid == (
        InvalidEntry(index=0, uuid=None, reason="entry is not a table"),
        InvalidEntry(index=1, uuid=None, reason="entry is not a table"),
    )


def test_one_invalid_entry_leaves_the_others_working():
    text = raw_registry_text(
        [
            raw_volume_table(volume_fields(PERSONAL)),
            raw_volume_table(volume_fields(MEDIABOX) | {"fstype": "ext4"}),
        ]
    )

    registry = parse(text, mount_base=MOUNT_BASE)

    assert registry.volumes == (PERSONAL_VOLUME,)
    assert [entry.index for entry in registry.invalid] == [1]


def test_invalid_entries_keep_file_positions():
    tables = [
        raw_volume_table(volume_fields(volume)) for volume in builders.many_volumes(4)
    ]
    tables[1] = raw_volume_table({"name": "bad name"})
    tables[3] = raw_volume_table({"name": "x", "key": TEST_KEY})

    registry = parse(raw_registry_text(tables))

    assert [entry.index for entry in registry.invalid] == [1, 3]
    assert [volume.name for volume in registry.volumes] == ["DRIVE000", "DRIVE002"]


# --- AC-005: the registry never holds a key -------------------------------------------


@pytest.mark.parametrize(
    "key", ["key", "password", "passphrase", "recovery_key", "secret"]
)
def test_registry_never_holds_key(key):
    registry = _parse_one(**{key: TEST_KEY})

    assert registry.volumes == ()
    assert registry.invalid == (
        InvalidEntry(index=0, uuid="01D95F1575592A30", reason=f"unknown key {key!r}"),
    )
    assert TEST_KEY not in repr(registry)
    assert TEST_KEY not in emit(registry)


# A key pasted as a TOML key name never reaches a reason: only identifier-like
# names (^[a-z][a-z0-9_]{0,31}$) are quoted, for typo diagnosis.
PASTED_KEY_NAMES = (
    "123456-234567-345678-456789-567890-678901-789012-890123",  # recovery key
    "Tr0ub4dor-And-Correct-Horse-Battery-Staple-9xQ",  # long, mixed case
    "a" * 33,  # one over the identifier length
    "Pathh",  # upper case
    "_path",  # does not start with a letter
)


@pytest.mark.parametrize("name", ["pathh", "x", "a" * 32, "drivers_2"])
def test_an_identifier_like_unknown_key_is_named(name):
    registry = _parse_one(**{name: True})

    assert [entry.reason for entry in registry.invalid] == [f"unknown key {name!r}"]


@pytest.mark.parametrize(
    "name",
    PASTED_KEY_NAMES,
    ids=["recovery-key", "mixed-case", "33-chars", "upper-case", "underscore-first"],
)
def test_any_other_unknown_key_is_not_named(name):
    registry = _parse_one(**{name: True})

    shown = name in repr(registry)
    assert [entry.reason for entry in registry.invalid] == ["unknown key"]
    assert not shown


def test_volume_type_has_no_field_for_a_key():
    assert [field.name for field in dataclasses.fields(Volume)] == [
        "name", "uuid", "path", "fstype", "drivers", "nosuid", "nodev",
    ]  # fmt: skip


def test_reasons_never_echo_a_value():
    registry = _parse_one(name=TEST_KEY + " ", path=TEST_KEY)

    assert TEST_KEY not in registry.invalid[0].reason


# --- cross-entry rules ----------------------------------------------------------------


def _three(first: dict, second: dict) -> str:
    """A text with MEDIABOX changed, PERSONAL changed, and an untouched third."""
    third = builders.RegistryVolume(
        name="GAMES", uuid="C40C-B21F", path="/run/media/deck/GAMES", fstype="exfat"
    )
    return raw_registry_text(
        [
            raw_volume_table(volume_fields(MEDIABOX) | first),
            raw_volume_table(volume_fields(PERSONAL) | second),
            raw_volume_table(volume_fields(third)),
        ]
    )


@pytest.mark.parametrize(
    ("first", "second", "reason"),
    [
        ({"uuid": "AAAA-BBBB"}, {"uuid": "aaaa-bbbb"}, "duplicate uuid"),
        ({"name": "DRIVE"}, {"name": "drive"}, "duplicate name"),
        (
            {"path": "/run/media/deck/x"},
            {"path": "/run/media/deck/x"},
            "duplicate path",
        ),
    ],
)
def test_duplicate_uuid_name_path_refused(first, second, reason):
    registry = parse(_three(first, second), mount_base=MOUNT_BASE)

    assert [volume.name for volume in registry.volumes] == ["GAMES"]
    assert [(entry.index, entry.reason) for entry in registry.invalid] == [
        (0, reason),
        (1, reason),
    ]


def test_path_sharing_a_prefix_is_not_a_duplicate():
    registry = parse(
        _three({"path": "/run/media/deck/A"}, {"path": "/run/media/deck/AB"}),
        mount_base=MOUNT_BASE,
    )

    assert registry.invalid == ()


@pytest.mark.parametrize("inner", ["/run/media/deck/x/y", "/run/media/deck/x/y/z"])
def test_nested_paths_leave_only_the_inner_entry_invalid(inner):
    """Since rule 9 two valid entries cannot nest: the inner one is refused on
    its own (DD-34), and the outer one still works."""
    registry = parse(
        _three({"path": "/run/media/deck/x"}, {"path": inner}), mount_base=MOUNT_BASE
    )

    assert [volume.name for volume in registry.volumes] == ["MEDIABOX", "GAMES"]
    assert registry.invalid == (
        InvalidEntry(
            index=1, uuid="658207d5-5177-4a52-a297-31643c64724d", reason=NOT_BASE_CHILD
        ),
    )


def test_path_outside_the_base_is_one_more_invalid_entry():
    """Rule 9 on every read (DD-34): the entry is invalid like any other, its
    UUID still blocks auto-mounting, and every other entry works."""
    registry = parse(
        _three({"path": "/home/deck/Drives/MEDIABOX"}, {}), mount_base=MOUNT_BASE
    )

    assert [volume.name for volume in registry.volumes] == ["PERSONAL", "GAMES"]
    assert registry.invalid == (
        InvalidEntry(index=0, uuid="01D95F1575592A30", reason=NOT_BASE_CHILD),
    )
    assert "01d95f1575592a30" in registry.blocked_uuids()


def test_parse_without_a_mount_base_uses_the_steamos_base():
    """``parse(text)`` (the Design Doc signature) must not mark every base
    child invalid: without a platform it applies the SteamOS mount base."""
    registry = parse(DESIGN_EXAMPLE)

    assert [volume.name for volume in registry.volumes] == ["MEDIABOX", "PERSONAL"]
    assert registry.invalid == ()
    assert parse(_one_entry(path="/mnt/x")).invalid[0].reason == NOT_BASE_CHILD


def test_default_mount_base_is_the_steamos_platform_base():
    assert config.DEFAULT_MOUNT_BASE == steamos.MOUNT_BASE


def test_duplicate_of_an_invalid_entry_does_not_spread():
    registry = parse(
        _three({"uuid": "AAAA-BBBB", "fstype": "ext4"}, {"uuid": "AAAA-BBBB"}),
        mount_base=MOUNT_BASE,
    )

    assert [volume.name for volume in registry.volumes] == ["PERSONAL", "GAMES"]
    assert registry.invalid == (
        InvalidEntry(
            index=0, uuid="AAAA-BBBB", reason="fstype: not a supported filesystem type"
        ),
    )


def test_three_way_duplicate_marks_all_three():
    tables = [
        raw_volume_table(
            volume_fields(
                dataclasses.replace(MEDIABOX, name=f"N{i}", path=f"{MOUNT_BASE}/N{i}")
            )
        )
        for i in range(3)
    ]

    registry = parse(raw_registry_text(tables))

    assert registry.volumes == ()
    assert [entry.reason for entry in registry.invalid] == ["duplicate uuid"] * 3


# --- blocked_uuids (Data Contracts invariant) -----------------------------------------


def test_blocked_uuids_include_invalid_entries_with_a_valid_uuid():
    text = raw_registry_text(
        [
            raw_volume_table(volume_fields(PERSONAL)),
            raw_volume_table(volume_fields(MEDIABOX) | {"key": TEST_KEY}),
            raw_volume_table({"name": "X", "uuid": "nope"}),
        ]
    )

    registry = parse(text, mount_base=MOUNT_BASE)

    assert registry.blocked_uuids() == frozenset(
        {"658207d5-5177-4a52-a297-31643c64724d", "01d95f1575592a30"}
    )


# --- emit -----------------------------------------------------------------------------


def test_emit_writes_the_design_doc_example_byte_for_byte():
    registry = Registry(
        schema_version=1, volumes=(PERSONAL_VOLUME, MEDIABOX_VOLUME), invalid=()
    )

    assert emit(registry) == DESIGN_EXAMPLE


def test_emit_of_the_empty_registry():
    assert emit(EMPTY) == EMPTY_TEXT


def test_emit_writes_every_driver_token_and_false_flags():
    steps = tuple(
        Step(driver, mode) for driver in (Driver.NTFS, Driver.NTFS3G) for mode in Mode
    )
    volume = dataclasses.replace(
        MEDIABOX_VOLUME, drivers=steps, nosuid=False, nodev=False
    )

    text = emit(Registry(schema_version=1, volumes=(volume,), invalid=()))

    assert text == HEADER + (
        "schema_version = 1\n"
        "\n"
        "[[volume]]\n"
        'name = "MEDIABOX"\n'
        'uuid = "01D95F1575592A30"\n'
        'path = "/run/media/deck/MEDIABOX"\n'
        'fstype = "ntfs"\n'
        'drivers = ["ntfs", "ntfs:ro", "ntfs-3g", "ntfs-3g:ro"]\n'
        "nosuid = false\n"
        "nodev = false\n"
    )


def test_emit_escapes_backslash_quote_and_control_characters():
    volume = dataclasses.replace(
        MEDIABOX_VOLUME, path='/run/media/deck/a"b\\c\x00d\x1fe\x7ff\tgé'
    )

    text = emit(Registry(schema_version=1, volumes=(volume,), invalid=()))

    assert (
        'path = "/run/media/deck/a\\"b\\\\c\\u0000d\\u001Fe\\u007Ff\\u0009gé"\n'
    ) in text


def test_emit_leaves_out_invalid_entries():
    registry = Registry(
        schema_version=1,
        volumes=(MEDIABOX_VOLUME,),
        invalid=(InvalidEntry(index=1, uuid="C40C-B21F", reason="unknown key 'key'"),),
    )

    assert emit(registry) == registry_text((MEDIABOX,))


def test_emit_then_parse_round_trips_the_example():
    registry = parse(DESIGN_EXAMPLE, mount_base=MOUNT_BASE)

    assert parse(emit(registry), mount_base=MOUNT_BASE) == registry


# --- NFR-25: no volume-count limit ----------------------------------------------------


def test_many_volumes_no_limit():
    volumes = builders.many_volumes(50)
    text = registry_text(volumes)

    registry = parse(text, mount_base=MOUNT_BASE)

    assert registry.invalid == ()
    assert len(registry.volumes) == 50
    assert {volume.uuid for volume in registry.volumes} == {v.uuid for v in volumes}
    assert emit(registry) == text
    assert parse(emit(registry), mount_base=MOUNT_BASE) == registry


# --- with_volume, without_volume ------------------------------------------------------


def test_with_volume_adds_and_sorts_by_name():
    registry = with_volume(Registry(1, (PERSONAL_VOLUME,), ()), MEDIABOX_VOLUME)

    assert registry == Registry(1, (MEDIABOX_VOLUME, PERSONAL_VOLUME), ())


def test_with_volume_keeps_invalid_entries():
    invalid = (InvalidEntry(index=0, uuid=None, reason="entry is not a table"),)

    registry = with_volume(Registry(1, (), invalid), MEDIABOX_VOLUME)

    assert registry.invalid == invalid


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        (
            {"uuid": "01d95f1575592a30", "name": "OTHER", "path": f"{MOUNT_BASE}/O"},
            "duplicate uuid",
        ),
        (
            {"uuid": "AAAA-BBBB", "name": "mediabox", "path": f"{MOUNT_BASE}/O"},
            "duplicate name",
        ),
        ({"uuid": "AAAA-BBBB", "name": "OTHER"}, "duplicate path"),
        (
            {
                "uuid": "AAAA-BBBB",
                "name": "OTHER",
                "path": "/run/media/deck/MEDIABOX/in",
            },
            NOT_BASE_CHILD,
        ),
    ],
)
def test_with_volume_refuses_duplicates_and_nesting(changes, reason):
    volume = dataclasses.replace(MEDIABOX_VOLUME, **changes)

    with pytest.raises(RefusedError) as raised:
        with_volume(Registry(1, (MEDIABOX_VOLUME,), ()), volume)

    assert str(raised.value) == reason


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"name": "bad name"}, "name: not a valid registry name"),
        ({"uuid": "nope"}, "uuid: not a valid UUID"),
        ({"path": "/etc/x"}, "path is at or under a system directory"),
        ({"path": "/mnt/x"}, NOT_BASE_CHILD),
        ({"path": "/home/deck/Drives/x"}, NOT_BASE_CHILD),
        ({"fstype": "ext4"}, "fstype: not a supported filesystem type"),
        (
            {"fstype": "exfat", "drivers": (Step(Driver.NTFS3, Mode.RW),)},
            "drivers: only for ntfs or BitLocker",
        ),
        ({"drivers": ()}, "drivers: must not be empty"),
    ],
)
def test_with_volume_refuses_a_volume_a_read_would_reject(changes, reason):
    volume = dataclasses.replace(MEDIABOX_VOLUME, **changes)

    with pytest.raises(RefusedError) as raised:
        with_volume(EMPTY, volume)

    assert str(raised.value) == reason


def test_without_volume_removes_by_name_case_insensitively():
    registry = Registry(1, (MEDIABOX_VOLUME, PERSONAL_VOLUME), ())

    assert without_volume(registry, "mediabox") == Registry(1, (PERSONAL_VOLUME,), ())


def test_without_volume_refuses_an_unknown_name():
    with pytest.raises(UsageError) as raised:
        without_volume(Registry(1, (MEDIABOX_VOLUME,), ()), "GAMES")

    assert str(raised.value) == "no registered volume is called GAMES"


# --- load: owner, mode, symlinks and the absent file (I001) ---------------------------


def test_absent_file_is_empty_registry(ctx, etc_dir):
    assert load(ctx) == Registry(schema_version=1, volumes=(), invalid=())


def test_absent_directory_is_unusable(ctx):
    with pytest.raises(RegistryError) as raised:
        load(ctx)

    assert raised.value.detail == "/etc/steamos-mounter is missing: install has not run"


def test_load_reads_a_good_file(ctx, etc_dir):
    _write_registry(etc_dir, DESIGN_EXAMPLE)

    assert load(ctx) == Registry(1, (MEDIABOX_VOLUME, PERSONAL_VOLUME), ())


def test_load_checks_paths_against_the_platform_mount_base(ctx, etc_dir):
    _write_registry(etc_dir, _one_entry(path=MOUNT_BASE))

    registry = load(ctx)

    assert registry.invalid[0].reason == "path is the mount base or one of its parents"


@pytest.mark.parametrize("mode", [0o664, 0o646, 0o666])
def test_file_writable_by_group_or_other_is_unusable(ctx, etc_dir, mode):
    _write_registry(etc_dir, DESIGN_EXAMPLE, mode=mode)

    with pytest.raises(RegistryError) as raised:
        load(ctx)

    assert raised.value.detail.startswith("/etc/steamos-mounter/config.toml: mode ")


@pytest.mark.parametrize("mode", [0o775, 0o757, 0o777])
def test_directory_writable_by_group_or_other_is_unusable(ctx, etc_dir, mode):
    etc_dir.chmod(mode)

    with pytest.raises(RegistryError) as raised:
        load(ctx)

    assert raised.value.detail.startswith("/etc/steamos-mounter: mode ")


def test_registry_owned_by_someone_else_is_unusable(ctx, etc_dir):
    _write_registry(etc_dir, DESIGN_EXAMPLE)
    other = dataclasses.replace(
        ctx, platform=dataclasses.replace(ctx.platform, trusted_uid=os.getuid() + 1)
    )

    with pytest.raises(RegistryError) as raised:
        load(other)

    assert (
        raised.value.detail
        == f"/etc/steamos-mounter: owned by uid {os.getuid()}, not {os.getuid() + 1}"
    )


def test_symlinked_file_is_unusable(ctx, etc_dir, tmp_path):
    real = tmp_path / "elsewhere.toml"
    real.write_text(DESIGN_EXAMPLE, encoding="utf-8")
    real.chmod(0o644)
    (etc_dir / "config.toml").symlink_to(real)

    with pytest.raises(RegistryError) as raised:
        load(ctx)

    assert raised.value.detail == "/etc/steamos-mounter/config.toml: is a symlink"


def test_dangling_symlink_is_unusable_not_absent(ctx, etc_dir, tmp_path):
    (etc_dir / "config.toml").symlink_to(tmp_path / "missing.toml")

    with pytest.raises(RegistryError):
        load(ctx)


def test_symlinked_directory_is_unusable(ctx, tmp_path):
    real = tmp_path / "real-etc"
    real.mkdir(mode=0o755)
    (tmp_path / "etc").mkdir()
    (tmp_path / ETC).symlink_to(real)

    with pytest.raises(RegistryError) as raised:
        load(ctx)

    assert raised.value.detail == "/etc/steamos-mounter: is a symlink"


def test_directory_in_place_of_the_file_is_unusable(ctx, etc_dir):
    (etc_dir / "config.toml").mkdir()

    with pytest.raises(RegistryError) as raised:
        load(ctx)

    assert (
        raised.value.detail == "/etc/steamos-mounter/config.toml: is not a regular file"
    )


def test_invalid_utf8_is_unusable(ctx, etc_dir):
    path = _write_registry(etc_dir, "")
    path.write_bytes(HEADER.encode() + b"schema_version = 1\n# \xff\n")

    with pytest.raises(RegistryError) as raised:
        load(ctx)

    assert raised.value.detail == "/etc/steamos-mounter/config.toml: not valid UTF-8"


@pytest.mark.skipif(os.getuid() == 0, reason="root reads any file")
def test_unreadable_file_is_unusable(ctx, etc_dir):
    _write_registry(etc_dir, DESIGN_EXAMPLE, mode=0o200)

    with pytest.raises(RegistryError) as raised:
        load(ctx)

    assert raised.value.detail == (
        "/etc/steamos-mounter/config.toml: cannot be read: Permission denied"
    )


def test_parse_failure_in_load_names_the_file(ctx, etc_dir):
    _write_registry(etc_dir, raw_registry_text([], top="schema_version = 2"))

    with pytest.raises(RegistryError) as raised:
        load(ctx)

    assert (
        raised.value.detail
        == "/etc/steamos-mounter/config.toml: schema_version is not 1"
    )


# --- save: the locked atomic write ----------------------------------------------------


def test_save_creates_the_first_registry_with_mode_0644(ctx, etc_dir, locks_dir):
    save(ctx, Registry(1, (MEDIABOX_VOLUME,), ()))

    path = etc_dir / "config.toml"
    assert path.read_text(encoding="utf-8") == registry_text((MEDIABOX,))
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o644
    assert os.lstat(path).st_uid == os.getuid()
    assert load(ctx) == Registry(1, (MEDIABOX_VOLUME,), ())


def test_save_replaces_a_good_registry(ctx, etc_dir, locks_dir):
    _write_registry(etc_dir, DESIGN_EXAMPLE)

    save(ctx, Registry(1, (PERSONAL_VOLUME,), ()))

    assert (etc_dir / "config.toml").read_text(encoding="utf-8") == registry_text(
        (PERSONAL,)
    )
    assert sorted(os.listdir(etc_dir)) == ["config.toml"]


@pytest.mark.parametrize(
    "broken",
    [HEADER + "schema_version = [\n", raw_registry_text([], top="schema_version = 9")],
)
def test_save_refuses_to_overwrite_an_unusable_file(ctx, etc_dir, locks_dir, broken):
    _write_registry(etc_dir, broken)

    with pytest.raises(RegistryError):
        save(ctx, Registry(1, (MEDIABOX_VOLUME,), ()))

    assert (etc_dir / "config.toml").read_text(encoding="utf-8") == broken
    assert sorted(os.listdir(etc_dir)) == ["config.toml"]


def test_save_refuses_when_the_file_has_a_bad_mode(ctx, etc_dir, locks_dir):
    _write_registry(etc_dir, DESIGN_EXAMPLE, mode=0o666)

    with pytest.raises(RegistryError):
        save(ctx, EMPTY)

    assert (etc_dir / "config.toml").read_text(encoding="utf-8") == DESIGN_EXAMPLE


def test_save_refuses_without_the_directory(ctx, locks_dir, tmp_path):
    with pytest.raises(RegistryError):
        save(ctx, Registry(1, (MEDIABOX_VOLUME,), ()))

    assert not (tmp_path / ETC).exists()


def test_save_waits_for_the_registry_lock(ctx, etc_dir, locks_dir):
    errors: list[BaseException] = []

    def saver() -> None:
        try:
            save(ctx, Registry(1, (MEDIABOX_VOLUME,), ()))
        except BaseException as error:  # noqa: BLE001 - reported by the assert below
            errors.append(error)

    with registry_lock(ctx, timeout=1.0):
        thread = threading.Thread(target=saver)
        thread.start()
        time.sleep(0.3)
        assert not (etc_dir / "config.toml").exists()
    thread.join(5.0)

    assert errors == []
    assert (etc_dir / "config.toml").is_file()


def test_save_does_not_wire(ctx, etc_dir, locks_dir, fake_runner):
    save(ctx, Registry(1, (MEDIABOX_VOLUME,), ()))

    assert fake_runner.calls == []


def test_registry_path_constants():
    assert config.REGISTRY_PATH == "/etc/steamos-mounter/config.toml"
    assert config.SCHEMA_VERSION == 1


# --- update: one read-modify-write under one hold of the registry lock -------------


def test_two_interleaved_updates_both_survive(ctx, etc_dir, locks_dir):
    """The second update reads after the first wrote: no lost update."""
    first_inside = threading.Event()
    release_first = threading.Event()
    errors: list[BaseException] = []

    def add_mediabox(current: Registry) -> Registry:
        first_inside.set()
        release_first.wait(5.0)
        return with_volume(current, MEDIABOX_VOLUME)

    def first() -> None:
        try:
            config.update(ctx, add_mediabox)
        except BaseException as error:  # noqa: BLE001 - reported by the assert below
            errors.append(error)

    thread = threading.Thread(target=first)
    thread.start()
    assert first_inside.wait(5.0)
    second = threading.Thread(
        target=lambda: config.update(
            ctx, lambda current: with_volume(current, PERSONAL_VOLUME)
        )
    )
    second.start()
    time.sleep(0.2)  # the second update is now waiting for the lock
    release_first.set()
    thread.join(5.0)
    second.join(5.0)

    assert errors == []
    assert [volume.name for volume in load(ctx).volumes] == ["MEDIABOX", "PERSONAL"]


def test_update_writes_nothing_when_the_change_refuses(ctx, etc_dir, locks_dir):
    _write_registry(etc_dir, DESIGN_EXAMPLE)

    def refuse(_current: Registry) -> Registry:
        raise RefusedError("duplicate name")

    with pytest.raises(RefusedError):
        config.update(ctx, refuse)

    assert (etc_dir / "config.toml").read_text(encoding="utf-8") == DESIGN_EXAMPLE


def test_update_runs_then_with_the_written_registry_under_the_lock(
    ctx, etc_dir, locks_dir
):
    seen = []

    def then(saved: Registry) -> None:
        with (
            pytest.raises(config.locks.LockTimeout),
            registry_lock(ctx, timeout=0.0),
        ):
            pass
        seen.append((saved, load(ctx)))

    result = config.update(
        ctx, lambda current: with_volume(current, MEDIABOX_VOLUME), then=then
    )

    assert seen == [(result, result)]
    assert result.volumes == (MEDIABOX_VOLUME,)


def test_update_refuses_an_unusable_registry(ctx, etc_dir, locks_dir):
    _write_registry(etc_dir, raw_registry_text([], top="schema_version = 9"))

    with pytest.raises(RegistryError):
        config.update(ctx, lambda current: current)


def test_with_volume_checks_rule_9_against_the_given_base():
    elsewhere = dataclasses.replace(MEDIABOX_VOLUME, path="/media/MEDIABOX")

    assert with_volume(EMPTY, elsewhere, mount_base="/media").volumes == (elsewhere,)
    with pytest.raises(RefusedError, match=NOT_BASE_CHILD):
        with_volume(EMPTY, elsewhere)


# --- no rewrite of a registry with invalid entries (owner decision 2026-10-11) ------

# PERSONAL, the second [[volume]], breaks rule 9.
ONE_INVALID = DESIGN_EXAMPLE.replace(
    'path = "/run/media/deck/PERSONAL"', 'path = "/mnt/PERSONAL"'
)
ONE_INVALID_MESSAGE = (
    "the registry has an invalid entry: [[volume]] number 2. Fix or remove it in"
    " /etc/steamos-mounter/config.toml first"
)
ONE_INVALID_DETAIL = "registry not rewritten: [[volume]] number 2: " + NOT_BASE_CHILD


REWRITES = {
    "save": lambda ctx: save(ctx, Registry(1, (MEDIABOX_VOLUME,), ())),
    "update": lambda ctx: config.update(ctx, lambda current: current),
}


@pytest.mark.parametrize("rewrite", ["save", "update"])
def test_a_registry_with_an_invalid_entry_is_never_rewritten(
    ctx, etc_dir, locks_dir, rewrite
):
    path = _write_registry(etc_dir, ONE_INVALID)
    before = path.read_bytes()

    with pytest.raises(RegistryError) as raised:
        REWRITES[rewrite](ctx)

    assert raised.value.exit_code == ExitCode.FAILED
    assert raised.value.user_message == ONE_INVALID_MESSAGE
    assert raised.value.detail == ONE_INVALID_DETAIL
    assert path.read_bytes() == before
    assert sorted(os.listdir(etc_dir)) == ["config.toml"]


def test_update_refuses_before_the_change_and_then_run(ctx, etc_dir, locks_dir):
    _write_registry(etc_dir, ONE_INVALID)
    seen: list[str] = []

    def change(current: Registry) -> Registry:
        seen.append("change")
        return current

    with pytest.raises(RegistryError):
        config.update(ctx, change, then=lambda _saved: seen.append("then"))

    assert seen == []


def test_every_invalid_entry_is_named_by_number_with_its_reason(
    ctx, etc_dir, locks_dir
):
    """Entries 1 and 3 clash, entry 2 is a bad type; entry 4 is valid."""
    games = volume_fields(MEDIABOX) | {"name": TEST_KEY, "fstype": "ext4"}
    twin = volume_fields(MEDIABOX) | {"name": "TWIN", "path": f"{MOUNT_BASE}/TWIN"}
    tables = [
        raw_volume_table(volume_fields(MEDIABOX)),
        raw_volume_table(games | {"uuid": "1234-ABCD", "path": f"{MOUNT_BASE}/G"}),
        raw_volume_table(twin),
        raw_volume_table(volume_fields(PERSONAL)),
    ]
    _write_registry(etc_dir, raw_registry_text(tables))

    with pytest.raises(RegistryError) as raised:
        config.update(ctx, lambda current: current)

    error = raised.value
    leaked = TEST_KEY in error.user_message + error.detail + str(error)
    assert error.user_message == (
        "the registry has invalid entries: [[volume]] numbers 1, 2, 3. Fix or remove"
        " them in /etc/steamos-mounter/config.toml first"
    )
    assert error.detail == (
        "registry not rewritten: [[volume]] number 1: duplicate uuid;"
        " [[volume]] number 2: fstype: not a supported filesystem type;"
        " [[volume]] number 3: duplicate uuid"
    )
    assert not leaked


def test_a_registry_with_only_valid_entries_is_still_rewritten(ctx, etc_dir, locks_dir):
    _write_registry(etc_dir, DESIGN_EXAMPLE)

    result = config.update(ctx, lambda current: without_volume(current, "PERSONAL"))

    assert result.volumes == (MEDIABOX_VOLUME,)
    assert (etc_dir / "config.toml").read_text(encoding="utf-8") == registry_text(
        (MEDIABOX,)
    )
