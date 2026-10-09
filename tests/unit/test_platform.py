"""The platform seam: SteamOS facts, detection and the OS partition set.

Design Doc "Platform Seam", "OS Partition Set" and DD-02. The OS partition
sources are real files and real symlinks under ``HostPaths(root=tmp_path)``,
filled from the Deck captures ``udev-run-90-holo-partsets-all.rules.txt`` and
``efi-partsets-all.txt`` (rc 1: "Permission denied" as ``deck``).
"""

import dataclasses
import json
import os
from pathlib import Path

import pytest

from steamos_mounter.errors import ExitCode, MounterError, UnsupportedPlatformError
from steamos_mounter.platforms import current_platform, steamos
from steamos_mounter.platforms.base import (
    HostPaths,
    OsPartitionSet,
    Platform,
    SessionAllowList,
    SessionUser,
    Tools,
)
from steamos_mounter.platforms.steamos import SteamOSPlatform
from tests.helpers.fixtures import fixture_rc, load_fixture

RULES = "/run/udev/rules.d/90-holo-partsets-all.rules"
LINKS = "/dev/disk/by-partsets/all"
PARTSETS = "/efi/SteamOS/partsets/all"
RULES_FIXTURE = "udev-run-90-holo-partsets-all.rules.txt"
PARTSETS_FIXTURE = "efi-partsets-all.txt"
LSBLK_FIXTURE = "lsblk-columns-tree.json"

# The by-partsets link names in the rules capture, in partition order.
DECK_LINKS = {
    "esp": "nvme0n1p1",
    "efi-A": "nvme0n1p2",
    "efi-B": "nvme0n1p3",
    "rootfs-A": "nvme0n1p4",
    "rootfs-B": "nvme0n1p5",
    "var-A": "nvme0n1p6",
    "var-B": "nvme0n1p7",
    "home": "nvme0n1p8",
}
NVME_PARTITIONS = frozenset(DECK_LINKS.values())
RULES_PARTUUIDS = frozenset(
    {
        "584a6949-4802-4d5a-b558-ceacc6c4852d",
        "97ae233c-11ec-4118-8b76-23042b95eb25",
        "84394af6-37f5-4f6d-9e46-be3ca9966ad7",
        "eb6fd94f-2112-49fb-b983-2671ba171406",
        "01ae6e72-9609-434f-a3cc-4c046d128206",
        "65f65ea0-0112-43c7-9f35-46be5c3a25b4",
        "f3331961-6666-495d-8e08-7c9ab9aa8f0b",
        "afc32485-4f6b-4972-a880-a6fb77f8940d",
    }
)
# Only in the root-only partsets file of the tests below (not on the Deck).
PARTSETS_ONLY_UUID = "0b5e3c1a-2d4f-4a6b-8c9d-0e1f2a3b4c5d"
EXTERNAL_DEVICES = ("sda1", "sdb1", "sdb2", "sdb5", "dm-0", "mmcblk0p1")
CLI_ROOT = "sudo /opt/steamos-mounter/bin/steamos-mounter"
TOOL_NAMES = {
    "mount": "mount",
    "umount": "umount",
    "findmnt": "findmnt",
    "lsblk": "lsblk",
    "cryptsetup": "cryptsetup",
    "dmsetup": "dmsetup",
    "ntfs3g": "ntfs-3g",
    "ntfs3g_probe": "ntfs-3g.probe",
    "systemctl": "systemctl",
    "systemd_run": "systemd-run",
    "udevadm": "udevadm",
    "loginctl": "loginctl",
    "kdialog": "kdialog",
    "zenity": "zenity",
    "notify_send": "notify-send",
    "rsync": "rsync",
    "setfacl": "setfacl",
}


def write(root: Path, absolute: str, data: bytes, *, mode: int = 0o644) -> Path:
    path = root / absolute.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def link_deck_partsets(host_tree) -> None:
    for name, kname in DECK_LINKS.items():
        host_tree.link_by_partsets(name, kname)


def partsets_file_text(*uuids: str) -> bytes:
    """``/efi/SteamOS/partsets/all`` layout: ``label uuid ignore`` per line."""
    lines = [f"part{index} {uuid} 0\n" for index, uuid in enumerate(uuids)]
    return "".join(lines).encode()


def deck_partitions() -> dict[str, str | None]:
    """kname -> PARTUUID of every partition and mapping in the lsblk capture."""
    found: dict[str, str | None] = {}
    stack = list(json.loads(load_fixture(LSBLK_FIXTURE))["blockdevices"])
    while stack:
        device = stack.pop()
        found[device["kname"]] = device["partuuid"]
        stack.extend(device.get("children", []))
    return found


def protocol_members(protocol: type) -> set[str]:
    methods = {
        name
        for name, value in vars(protocol).items()
        if callable(value) and not name.startswith("_")
    }
    return set(protocol.__annotations__) | methods


def public_names(instance: object) -> set[str]:
    return {name for name in dir(instance) if not name.startswith("_")}


# --- HostPaths -------------------------------------------------------------


def test_host_paths_maps_an_absolute_path_under_the_root(tmp_path):
    assert HostPaths(root=tmp_path).p("/etc/os-release") == tmp_path / "etc/os-release"


def test_host_paths_defaults_to_the_real_root():
    assert HostPaths().p("/etc/os-release") == Path("/etc/os-release")


# --- OsPartitionSet.contains -----------------------------------------------


def os_set(**overrides: object) -> OsPartitionSet:
    values: dict[str, object] = {
        "known": True,
        "knames": frozenset({"nvme0n1p8"}),
        "partuuids": frozenset({"afc32485-4f6b-4972-a880-a6fb77f8940d"}),
        "sources": (LINKS,),
    }
    values.update(overrides)
    return OsPartitionSet(**values)


def test_contains_matches_a_linked_kname():
    assert os_set().contains("nvme0n1p8", None) is True


def test_contains_matches_a_partuuid_in_any_case():
    found = os_set(knames=frozenset())

    assert found.contains("nvme0n1p8", "AFC32485-4F6B-4972-A880-A6FB77F8940D") is True


def test_contains_is_false_for_an_external_partition():
    assert os_set().contains("sdb5", "affac936-05") is False


def test_contains_is_false_without_a_partuuid_or_link():
    assert os_set().contains("sdb1", None) is False


# --- detect and current_platform -------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [("os-release-steamos.txt", True), ("os-release-debian.txt", False)],
)
def test_detect_reads_os_release(tmp_path, fixture, expected):
    write(tmp_path, "/etc/os-release", load_fixture(fixture))

    assert SteamOSPlatform().detect(HostPaths(root=tmp_path)) is expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('ID="steamos"\n', True),
        ("  ID=steamos  \n", True),
        ("ID=arch\nID_LIKE=steamos\n", False),
        ("ID=steamos-fork\n", False),
        ("ID='steamos'\n", False),
        ("", False),
    ],
)
def test_detect_follows_the_entry_point_id_rule(tmp_path, text, expected):
    write(tmp_path, "/etc/os-release", text.encode())

    assert SteamOSPlatform().detect(HostPaths(root=tmp_path)) is expected


def test_detect_is_false_without_os_release(tmp_path):
    assert SteamOSPlatform().detect(HostPaths(root=tmp_path)) is False


def test_detect_survives_undecodable_bytes(tmp_path):
    write(tmp_path, "/etc/os-release", b'NAME="\xff\xfe"\nID=steamos\n')

    assert SteamOSPlatform().detect(HostPaths(root=tmp_path)) is True


def test_current_platform_on_steamos_is_the_steamos_platform(tmp_path):
    write(tmp_path, "/etc/os-release", load_fixture("os-release-steamos.txt"))

    platform = current_platform(HostPaths(root=tmp_path))

    assert isinstance(platform, SteamOSPlatform)


def test_non_steamos_exit_4(tmp_path):
    """AC-051 detection half: a Debian host is refused with exit code 4."""
    write(tmp_path, "/etc/os-release", load_fixture("os-release-debian.txt"))

    with pytest.raises(UnsupportedPlatformError) as raised:
        current_platform(HostPaths(root=tmp_path))

    assert raised.value.exit_code is ExitCode.UNSUPPORTED_PLATFORM
    assert int(raised.value.exit_code) == 4
    assert raised.value.user_message == "unsupported platform: SteamOS only"


# --- SteamOS facts ---------------------------------------------------------


def test_steamos_tools_are_absolute_usr_bin_paths():
    tools = SteamOSPlatform().tools

    assert dataclasses.asdict(tools) == {
        field: f"/usr/bin/{name}" for field, name in TOOL_NAMES.items()
    }


def test_steamos_facts_match_the_platform_seam_table():
    platform = SteamOSPlatform()

    assert platform.name == "steamos"
    assert platform.mount_base == "/run/media/deck"
    assert platform.trusted_uid == 0
    assert platform.auto_fstypes == frozenset({"ntfs", "exfat", "vfat", "btrfs"})
    assert platform.registrable_fstypes == frozenset(
        {"ntfs", "exfat", "vfat", "btrfs", "BitLocker"}
    )
    assert platform.keep_list == "/usr/lib/rauc/atomic-update-keep.conf"
    assert platform.dropin_dir == "/etc/atomic-update.conf.d"
    assert platform.allow_list == SessionAllowList(
        seat="seat0",
        session_class="user",
        desktop=frozenset({"KDE"}),
        session_type=frozenset({"x11"}),
    )
    assert platform.xauthority_from_xserver is False
    assert platform.dialog_tool == "kdialog"
    assert platform.cli_root == CLI_ROOT


def test_steamos_platform_has_exactly_the_protocol_members():
    assert public_names(SteamOSPlatform()) == protocol_members(Platform)


def test_session_user_is_resolved_with_pwd_at_use_time(monkeypatch):
    # "root" exists in every image; the Deck's "deck" does not exist in Docker.
    monkeypatch.setattr(steamos, "SESSION_USER", "root")

    assert SteamOSPlatform().session_user() == SessionUser(
        name="root",
        uid=0,
        gid=0,
        runtime_dir="/run/user/0",
        bus_address="unix:path=/run/user/0/bus",
    )


def test_session_user_missing_is_a_mounter_error(monkeypatch):
    monkeypatch.setattr(steamos, "SESSION_USER", "no-such-user-sm")

    with pytest.raises(MounterError) as raised:
        SteamOSPlatform().session_user()

    assert raised.value.user_message == "session user not found"
    assert "no-such-user-sm" in raised.value.detail


# --- automount_lock_path ---------------------------------------------------


@pytest.mark.parametrize("kname", ["sdb5", "mmcblk0p1", "sda1", "nvme0n1p8"])
def test_automount_lock_path_for_holo_style_names(kname):
    expected = f"/var/run/jupiter-automount-{kname}.lock"

    assert SteamOSPlatform().automount_lock_path(kname) == expected


@pytest.mark.parametrize(
    "kname", ["dm-0", "SDB5", "sdb5\n", "", "../sdb5", "sdb 5", "loop0p1/x"]
)
def test_automount_lock_path_is_none_outside_the_regex(kname):
    assert SteamOSPlatform().automount_lock_path(kname) is None


# --- os_partitions ---------------------------------------------------------


def test_os_partition_sources(ctx, host_tree):
    """Links, the holo rules capture and the root-only partsets file, unioned."""
    link_deck_partsets(host_tree)
    write(ctx.paths.root, RULES, load_fixture(RULES_FIXTURE))
    write(
        ctx.paths.root,
        PARTSETS,
        partsets_file_text(*sorted(RULES_PARTUUIDS), PARTSETS_ONLY_UUID),
        mode=0o600,
    )

    found = SteamOSPlatform().os_partitions(ctx, as_root=True)

    assert found == OsPartitionSet(
        known=True,
        knames=NVME_PARTITIONS,
        partuuids=RULES_PARTUUIDS | {PARTSETS_ONLY_UUID},
        sources=(LINKS, RULES, PARTSETS),
    )


def test_os_set_from_the_deck_sources_marks_every_nvme_partition(ctx, host_tree):
    link_deck_partsets(host_tree)
    write(ctx.paths.root, RULES, load_fixture(RULES_FIXTURE))

    found = SteamOSPlatform().os_partitions(ctx, as_root=True)

    partitions = deck_partitions()
    marked = {
        kname for kname, uuid in partitions.items() if found.contains(kname, uuid)
    }
    assert marked == NVME_PARTITIONS
    assert not any(
        found.contains(kname, partitions[kname]) for kname in EXTERNAL_DEVICES
    )


def test_rules_alone_mark_nvme_partitions_by_partuuid_as_deck(ctx_deck):
    """``scan`` as deck: the world-readable rules file is enough (EARS)."""
    write(ctx_deck.paths.root, RULES, load_fixture(RULES_FIXTURE))

    found = SteamOSPlatform().os_partitions(ctx_deck, as_root=False)

    assert found.known is True
    assert found.knames == frozenset()
    assert found.sources == (RULES,)
    partitions = deck_partitions()
    assert {k for k, uuid in partitions.items() if found.contains(k, uuid)} == (
        NVME_PARTITIONS
    )


def test_links_alone_make_the_set_known(ctx_deck, host_tree):
    link_deck_partsets(host_tree)

    found = SteamOSPlatform().os_partitions(ctx_deck, as_root=False)

    assert (found.known, found.knames, found.partuuids, found.sources) == (
        True,
        NVME_PARTITIONS,
        frozenset(),
        (LINKS,),
    )


def test_partsets_file_is_read_only_as_root(ctx_deck):
    write(ctx_deck.paths.root, PARTSETS, partsets_file_text(PARTSETS_ONLY_UUID))

    found = SteamOSPlatform().os_partitions(ctx_deck, as_root=False)

    assert found.known is False
    assert found.partuuids == frozenset()


def test_partsets_file_alone_makes_the_set_known_as_root(ctx):
    upper = PARTSETS_ONLY_UUID.upper()
    write(ctx.paths.root, PARTSETS, f"x {upper} 0\nnot-a-uuid y\n".encode())

    found = SteamOSPlatform().os_partitions(ctx, as_root=True)

    assert (found.known, found.partuuids, found.sources) == (
        True,
        frozenset({PARTSETS_ONLY_UUID}),
        (PARTSETS,),
    )


def test_unknown_set_when_nothing_is_readable(ctx):
    """DD-02 fail closed: no source at all -> ``known = False``."""
    found = SteamOSPlatform().os_partitions(ctx, as_root=True)

    assert found == OsPartitionSet(
        known=False, knames=frozenset(), partuuids=frozenset(), sources=()
    )
    assert found.contains("nvme0n1p8", "afc32485-4f6b-4972-a880-a6fb77f8940d") is False


def test_efi_partsets_capture_rc_1_is_treated_as_unreadable(ctx):
    """The Deck answered ``Permission denied`` (rc 1); it yields no entry."""
    assert fixture_rc(PARTSETS_FIXTURE) == 1
    write(ctx.paths.root, PARTSETS, load_fixture(PARTSETS_FIXTURE), mode=0o000)

    found = SteamOSPlatform().os_partitions(ctx, as_root=True)

    assert found.known is False
    assert found.sources == ()


def test_readable_but_empty_sources_leave_the_set_unknown(ctx):
    write(ctx.paths.root, RULES, b"# no partsets here\n")
    write(ctx.paths.root, PARTSETS, b"")
    (ctx.paths.root / LINKS.lstrip("/")).mkdir(parents=True)

    found = SteamOSPlatform().os_partitions(ctx, as_root=True)

    assert found.known is False


def test_links_resolving_outside_dev_are_ignored(ctx, tmp_path):
    links = tmp_path / LINKS.lstrip("/")
    links.mkdir(parents=True)
    (links / "stray").symlink_to(tmp_path / "elsewhere" / "nvme0n1p1")
    (links / "nested").symlink_to(tmp_path / "dev" / "mapper" / "rootfs")

    found = SteamOSPlatform().os_partitions(ctx, as_root=False)

    assert found.known is False


def test_rules_partuuids_are_lowercased(ctx):
    rule = 'ENV{ID_PART_ENTRY_UUID}=="AFC32485-4F6B-4972-A880-A6FB77F8940D"\n'
    write(ctx.paths.root, RULES, rule.encode())

    found = SteamOSPlatform().os_partitions(ctx, as_root=False)

    assert found.partuuids == frozenset({"afc32485-4f6b-4972-a880-a6fb77f8940d"})


# --- FakePlatform ----------------------------------------------------------


def test_fake_platform_has_exactly_the_protocol_members(fake_platform):
    assert public_names(fake_platform) == protocol_members(Platform)


def test_fake_platform_trusts_the_test_user(fake_platform):
    assert fake_platform.trusted_uid == os.getuid()


def test_fake_platform_keeps_the_steamos_facts(fake_platform):
    real = SteamOSPlatform()

    assert fake_platform.tools == real.tools
    assert all(path.startswith("/usr/bin/") for path in dataclasses.astuple(real.tools))
    assert fake_platform.mount_base == "/run/media/deck"
    assert fake_platform.allow_list == real.allow_list
    assert fake_platform.cli_root == CLI_ROOT
    assert fake_platform.auto_fstypes == real.auto_fstypes
    assert fake_platform.registrable_fstypes == real.registrable_fstypes


def test_fake_platform_session_user_is_the_deck_user(fake_platform):
    assert fake_platform.session_user() == SessionUser(
        name="deck",
        uid=1000,
        gid=1000,
        runtime_dir="/run/user/1000",
        bus_address="unix:path=/run/user/1000/bus",
    )


def test_fake_platform_reads_os_partitions_under_the_test_root(ctx, host_tree):
    link_deck_partsets(host_tree)

    found = ctx.platform.os_partitions(ctx, as_root=True)

    assert found.knames == NVME_PARTITIONS


def test_fake_platform_detects_and_locks_like_steamos(fake_platform, tmp_path):
    write(tmp_path, "/etc/os-release", load_fixture("os-release-steamos.txt"))

    assert fake_platform.detect(HostPaths(root=tmp_path)) is True
    assert fake_platform.automount_lock_path("dm-0") is None
    assert fake_platform.automount_lock_path("sdb5") == (
        "/var/run/jupiter-automount-sdb5.lock"
    )


def test_tools_is_a_frozen_dataclass():
    with pytest.raises(dataclasses.FrozenInstanceError):
        SteamOSPlatform().tools.mount = "/bin/mount"  # type: ignore[misc]
    assert isinstance(SteamOSPlatform().tools, Tools)
