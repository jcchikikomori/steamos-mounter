"""Shared enums and dataclasses (Design Doc "model, context, platforms")."""

import dataclasses

import pytest

from steamos_mounter.model import (
    Driver,
    InstanceKind,
    InvalidEntry,
    Mode,
    MountInfo,
    Registry,
    Step,
    Trigger,
    Volume,
    VolumeState,
)

MEDIABOX_UUID = "01D95F1575592A30"
PERSONAL_UUID = "B6A1E2C4-0D3F-4E5A-9B8C-7D6E5F4A3B21"


def volume(name: str, uuid: str) -> Volume:
    return Volume(
        name=name,
        uuid=uuid,
        path=f"/run/media/deck/{name}",
        fstype="ntfs",
        drivers=None,
        nosuid=True,
        nodev=True,
    )


def registry(*volumes: Volume, invalid: tuple[InvalidEntry, ...] = ()) -> Registry:
    return Registry(schema_version=1, volumes=volumes, invalid=invalid)


def mount_info(vfs: tuple[str, ...], fs: tuple[str, ...]) -> MountInfo:
    return MountInfo(
        target="/run/media/deck/MEDIABOX",
        source="/dev/sdb5",
        fstype="fuseblk",
        vfs_options=vfs,
        fs_options=fs,
        devnum="8:21",
    )


# --- enums -----------------------------------------------------------------


def test_enum_values_are_the_spellings_records_and_the_registry_use():
    assert [mode.value for mode in Mode] == ["rw", "ro"]
    assert [driver.value for driver in Driver] == [
        "ntfs3",
        "ntfs-3g",
        "ntfs",
        "exfat",
        "vfat",
        "btrfs",
    ]
    assert [kind.value for kind in InstanceKind] == ["registered", "auto"]
    assert [trigger.value for trigger in Trigger] == ["start", "reload", "cli"]


def test_volume_state_words_match_the_state_list():
    assert [state.value for state in VolumeState] == [
        "NotPresent",
        "NotMounted",
        "Locked",
        "NeedsKey",
        "UnlockFailed",
        "UnlockCancelled",
        "Mounting",
        "MountedRW",
        "MountedRWDirty",
        "MountedRO",
        "MountedElsewhere",
        "MountFailed",
        "MountTimedOut",
        "UnmountedByUser",
    ]


def test_driver_parses_from_its_registry_spelling():
    assert Driver("ntfs-3g") is Driver.NTFS3G
    assert str(Driver.NTFS3G) == "ntfs-3g"


# --- dataclasses -----------------------------------------------------------


@pytest.mark.parametrize(
    "instance",
    [
        Step(Driver.NTFS3, Mode.RW),
        volume("MEDIABOX", MEDIABOX_UUID),
        InvalidEntry(index=2, uuid=None, reason="missing path"),
        registry(),
        mount_info(("rw",), ("rw",)),
    ],
    ids=lambda instance: type(instance).__name__,
)
def test_dataclasses_are_frozen_and_slotted(instance):
    assert not hasattr(instance, "__dict__")
    field = dataclasses.fields(instance)[0].name
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(instance, field, None)


def test_steps_compare_by_value():
    assert Step(Driver.NTFS3G, Mode.RW) == Step(Driver.NTFS3G, Mode.RW)
    assert Step(Driver.NTFS3G, Mode.RW) != Step(Driver.NTFS3G, Mode.RO)


# --- Registry lookups ------------------------------------------------------


def test_by_uuid_ignores_case():
    mediabox = volume("MEDIABOX", MEDIABOX_UUID)

    found = registry(mediabox).by_uuid(MEDIABOX_UUID.lower())

    assert found is mediabox


def test_by_uuid_returns_none_for_an_unknown_uuid():
    assert registry(volume("MEDIABOX", MEDIABOX_UUID)).by_uuid("ABCD-1234") is None


def test_by_name_ignores_case():
    personal = volume("PERSONAL", PERSONAL_UUID)

    found = registry(volume("MEDIABOX", MEDIABOX_UUID), personal).by_name("personal")

    assert found is personal


def test_by_name_returns_none_for_an_unknown_name():
    assert registry(volume("MEDIABOX", MEDIABOX_UUID)).by_name("GAMES") is None


def test_blocked_uuids_holds_valid_and_invalid_entries_lowercased():
    invalid = (
        InvalidEntry(index=1, uuid="ABCD-1234", reason="bad path"),
        InvalidEntry(index=2, uuid=None, reason="missing uuid"),
    )

    blocked = registry(volume("MEDIABOX", MEDIABOX_UUID), invalid=invalid)

    assert blocked.blocked_uuids() == frozenset({"01d95f1575592a30", "abcd-1234"})


def test_blocked_uuids_of_an_empty_registry_is_empty():
    assert registry().blocked_uuids() == frozenset()


# --- MountInfo.read_only ---------------------------------------------------


@pytest.mark.parametrize(
    ("vfs", "fs", "expected"),
    [
        (("rw", "nosuid", "nodev"), ("rw", "user_id=0"), False),
        (("ro", "nosuid"), ("rw",), True),
        (("rw",), ("ro", "allow_other"), True),
        (("rw",), ("errors=remount-ro",), False),
        ((), (), False),
    ],
)
def test_read_only_needs_an_exact_ro_option(vfs, fs, expected):
    assert mount_info(vfs, fs).read_only is expected
