"""The views ``list`` shows, state words and next steps.

Design Doc "Runtime State Records", "State Transitions", "list and scan
Output", DD-22 and I006. The records are real files under
``HostPaths(root=tmp_path)``; views are computed from the real Deck lsblk
capture and findmnt read-backs (real or the synthetic V-11 stand-ins). The
runtime tree and the records themselves are tested in ``test_records.py``.
"""

import dataclasses
import json
from pathlib import Path

import pytest

from steamos_mounter import state
from steamos_mounter.blockdev import DeviceTree, parse_lsblk_json
from steamos_mounter.config import parse
from steamos_mounter.errors import RegistryError
from steamos_mounter.model import InstanceKind, MountInfo, VolumeState
from steamos_mounter.mounts import parse_findmnt
from steamos_mounter.records import ensure_runtime_dirs, record_path
from steamos_mounter.runner import CommandResult
from steamos_mounter.state import (
    VolumeView,
    compute_views,
    next_step,
    words,
)
from tests.helpers.builders import (
    MEDIABOX,
    PERSONAL,
    RECORD_EXAMPLE,
    RegistryVolume,
    lsblk_device,
    record_dict,
    registry_text,
)
from tests.helpers.fixtures import load_fixture

CLI = "sudo /opt/steamos-mounter/bin/steamos-mounter"
RUN = "run"
MEDIABOX_KEY = "01d95f1575592a30"
PERSONAL_KEY = "658207d5-5177-4a52-a297-31643c64724d"
MEDIABOX_PATH = "/run/media/deck/MEDIABOX"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
GAMES_PATH = "/run/media/deck/GAMES"
DECK_TREE = "lsblk-columns-tree.json"
TREE_WITH_GAMES = "lsblk-tree-with-exfat-sdc1.json"
UNSAFE_PHRASE = "unsafe state (hibernation, Fast Startup, or an abrupt unplug)"
DIRTY_WARNING = RECORD_EXAMPLE["warning"]


def _tree(name: str = DECK_TREE) -> DeviceTree:
    return parse_lsblk_json(load_fixture(name))


def _unplugged(tree: DeviceTree, *knames: str) -> DeviceTree:
    """``tree`` as lsblk shows it after ``knames`` went away."""
    return DeviceTree(
        devices={k: d for k, d in tree.devices.items() if k not in knames},
        parents={k: p for k, p in tree.parents.items() if k not in knames},
    )


def _findmnt(name: str) -> tuple[MountInfo, ...]:
    return parse_findmnt(
        CommandResult(
            argv=(),
            returncode=0,
            stdout=load_fixture(name),
            stderr=b"",
            secret=None,
            timed_out=False,
            not_found=False,
            overflow=False,
        )
    )


def _registry(*volumes: RegistryVolume):
    return parse(registry_text(volumes))


def _write_record(ctx, kind: InstanceKind, key: str, data: dict) -> Path:
    path = record_path(ctx, kind, key)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _registered(key: str, **changes) -> dict:
    return record_dict(kind="registered", key=key, **changes)


def _auto(key: str, **changes) -> dict:
    return record_dict(kind="auto", key=key, mapping=None, **changes)


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """``/run`` as it is after boot: present, without our tree."""
    directory = tmp_path / RUN
    directory.mkdir()
    return directory


@pytest.fixture
def runtime(ctx, run_dir) -> Path:
    """The tree a root entry has created."""
    ensure_runtime_dirs(ctx)
    return run_dir / "steamos-mounter"


# --- compute_views: registered volumes ------------------------------------------------


def _view(views: list[VolumeView], name: str) -> VolumeView:
    return next(view for view in views if view.name == name)


def test_registered_mount_shows_what_findmnt_shows_and_the_records_words(ctx, runtime):
    _write_record(
        ctx,
        InstanceKind.REGISTERED,
        MEDIABOX_KEY,
        _registered(MEDIABOX_KEY, name="MEDIABOX", warning="MEDIABOX is dirty."),
    )

    views = compute_views(
        ctx, _registry(MEDIABOX), _tree(), _findmnt("findmnt-mediabox-fuseblk-rw.json")
    )

    assert views == [
        VolumeView(
            name="MEDIABOX",
            uuid="01D95F1575592A30",
            kind=InstanceKind.REGISTERED,
            present=True,
            path=MEDIABOX_PATH,
            driver="ntfs-3g",
            mode="rw",
            state=VolumeState.MOUNTED_RW_DIRTY,
            reason="dirty",
            warning="MEDIABOX is dirty.",
            next_step="Run chkdsk /f on it in Windows.",
        )
    ]


def test_findmnt_wins_unmounted_by_user_while_the_device_is_present(ctx, runtime):
    _write_record(
        ctx,
        InstanceKind.REGISTERED,
        MEDIABOX_KEY,
        _registered(MEDIABOX_KEY, name="MEDIABOX", state="MountedRW", reason=None),
    )

    (view,) = compute_views(ctx, _registry(MEDIABOX), _tree(), ())

    assert view.state is VolumeState.UNMOUNTED_BY_USER
    assert view.present is True
    assert (view.driver, view.mode, view.reason, view.warning) == (
        None,
        None,
        None,
        None,
    )
    assert view.next_step == f"Run {CLI} mount --volume MEDIABOX, or replug the drive."


def test_findmnt_wins_not_present_when_the_device_is_gone(ctx, runtime):
    _write_record(
        ctx,
        InstanceKind.REGISTERED,
        MEDIABOX_KEY,
        _registered(MEDIABOX_KEY, name="MEDIABOX"),
    )

    (view,) = compute_views(ctx, _registry(MEDIABOX), _unplugged(_tree(), "sdb5"), ())

    assert view.state is VolumeState.NOT_PRESENT
    assert view.present is False
    assert view.next_step == "Plug the drive in."


def test_findmnt_read_only_beats_a_record_that_says_read_write(ctx, runtime):
    _write_record(
        ctx,
        InstanceKind.REGISTERED,
        MEDIABOX_KEY,
        _registered(MEDIABOX_KEY, name="MEDIABOX", state="MountedRW", reason=None),
    )

    (view,) = compute_views(
        ctx, _registry(MEDIABOX), _tree(), _findmnt("findmnt-fuseblk-ro.json")
    )

    assert view.state is VolumeState.MOUNTED_RO
    assert (view.driver, view.mode, view.reason, view.warning) == (
        "ntfs-3g",
        "ro",
        None,
        None,
    )
    assert view.next_step == "See journalctl -t steamos-mounter SM_VOLUME=MEDIABOX."


def test_unsafe_read_only_mount_keeps_the_records_reason_and_warning(ctx, runtime):
    warning = state.warning(VolumeState.MOUNTED_RO, "unsafe", name="MEDIABOX")
    _write_record(
        ctx,
        InstanceKind.REGISTERED,
        MEDIABOX_KEY,
        _registered(
            MEDIABOX_KEY,
            name="MEDIABOX",
            state="MountedRO",
            reason="unsafe",
            warning=warning,
            next_step=None,
        ),
    )

    (view,) = compute_views(
        ctx, _registry(MEDIABOX), _tree(), _findmnt("findmnt-fuseblk-ro.json")
    )

    assert view.state is VolumeState.MOUNTED_RO
    assert view.reason == "unsafe"
    assert view.warning == warning
    assert "chkdsk /f" in view.next_step


def test_present_registered_volume_without_a_record_is_not_mounted(ctx, runtime):
    (view,) = compute_views(ctx, _registry(MEDIABOX), _tree(), ())

    assert view.state is VolumeState.NOT_MOUNTED
    assert view.present is True
    assert view.path == MEDIABOX_PATH
    assert view.next_step == f"Run {CLI} mount --volume MEDIABOX."


def test_absent_registered_volume_without_a_record_is_not_present(ctx, runtime):
    (view,) = compute_views(ctx, _registry(MEDIABOX), _unplugged(_tree(), "sdb5"), ())

    assert view.state is VolumeState.NOT_PRESENT
    assert view.present is False


def test_unreadable_registered_record_is_rebuilt_from_findmnt_and_lsblk(ctx, runtime):
    record_path(ctx, InstanceKind.REGISTERED, MEDIABOX_KEY).write_bytes(b"{")

    (view,) = compute_views(
        ctx, _registry(MEDIABOX), _tree(), _findmnt("findmnt-mediabox-fuseblk-rw.json")
    )

    assert view.state is VolumeState.MOUNTED_RW
    assert view.driver == "ntfs-3g"
    assert view.next_step == "-"


def test_needs_key_view_shows_the_records_reason_and_the_list_example_step(
    ctx, runtime
):
    _write_record(
        ctx,
        InstanceKind.REGISTERED,
        PERSONAL_KEY,
        _registered(
            PERSONAL_KEY,
            state="NeedsKey",
            reason="no_session",
            warning="The stored key did not work.",
            next_step=None,
            mapping=None,
            mount=None,
        ),
    )

    (view,) = compute_views(ctx, _registry(PERSONAL), _tree(), ())

    assert view.state is VolumeState.NEEDS_KEY
    assert view.present is True
    assert view.path == PERSONAL_PATH
    assert view.warning == "The stored key did not work."
    assert view.next_step == (
        "In Desktop Mode, replug the drive or run sudo /opt/steamos-mounter/bin/"
        "steamos-mounter mount --volume PERSONAL. Or run sudo /opt/steamos-mounter/"
        "bin/steamos-mounter set-key PERSONAL."
    )


def test_registered_container_unlocked_and_mounted_elsewhere(ctx, runtime):
    (view,) = compute_views(
        ctx,
        _registry(PERSONAL),
        _tree(),
        _findmnt("findmnt-list-dm0-at-udisks-path.json"),
    )

    assert view.state is VolumeState.MOUNTED_ELSEWHERE
    assert view.path == "/run/media/deck/PERSONAL1"
    assert view.mode == "rw"
    assert view.next_step == (
        f"Unmount it there, then run {CLI} mount --volume PERSONAL to use the fixed"
        " path."
    )


def test_mounting_record_with_nothing_mounted_yet_stays_mounting(ctx, runtime):
    _write_record(
        ctx,
        InstanceKind.REGISTERED,
        MEDIABOX_KEY,
        _registered(MEDIABOX_KEY, name="MEDIABOX", state="Mounting", next_step=None),
    )

    (view,) = compute_views(ctx, _registry(MEDIABOX), _tree(), ())

    assert view.state is VolumeState.MOUNTING
    assert view.next_step == "Wait a few seconds and run list again."


def test_record_of_a_mount_elsewhere_that_is_gone_is_not_mounted(ctx, runtime):
    _write_record(
        ctx,
        InstanceKind.REGISTERED,
        MEDIABOX_KEY,
        _registered(MEDIABOX_KEY, name="MEDIABOX", state="MountedElsewhere"),
    )

    (view,) = compute_views(ctx, _registry(MEDIABOX), _tree(), ())

    assert view.state is VolumeState.NOT_MOUNTED


def test_unusable_registry_gives_no_registered_rows(ctx, runtime):
    _write_record(
        ctx,
        InstanceKind.REGISTERED,
        MEDIABOX_KEY,
        _registered(MEDIABOX_KEY, name="MEDIABOX"),
    )

    views = compute_views(
        ctx, RegistryError("the registry cannot be used"), _tree(), ()
    )

    assert views == []


def test_empty_registry_gives_no_registered_rows(ctx, runtime):
    assert compute_views(ctx, _registry(), _tree(), ()) == []


# --- compute_views: auto volumes and ordering -----------------------------------------


def _games_record(key: str = "sdc1-8_33", **changes) -> dict:
    mount = {
        "status": "mounted",
        "target": GAMES_PATH,
        "device": "/dev/sdc1",
        "devnum": "8:33",
        "driver": "exfat",
        "mode": "rw",
        "created_dir": True,
    }
    values = {
        "name": "GAMES",
        "state": "MountedRW",
        "reason": None,
        "warning": None,
        "next_step": None,
        "mount": mount,
    } | changes
    return _auto(key, **values)


def test_auto_mount_view(ctx, runtime):
    _write_record(ctx, InstanceKind.AUTO, "sdc1-8_33", _games_record())

    (view,) = compute_views(
        ctx,
        _registry(),
        _tree(TREE_WITH_GAMES),
        _findmnt("findmnt-games-exfat-rw.json"),
    )

    assert view == VolumeView(
        name="GAMES",
        uuid="1234-ABCD",
        kind=InstanceKind.AUTO,
        present=True,
        path=GAMES_PATH,
        driver="exfat",
        mode="rw",
        state=VolumeState.MOUNTED_RW,
        reason=None,
        warning=None,
        next_step="-",
    )


def test_auto_record_unmounted_by_the_user(ctx, runtime):
    _write_record(ctx, InstanceKind.AUTO, "sdc1-8_33", _games_record())

    (view,) = compute_views(ctx, _registry(), _tree(TREE_WITH_GAMES), ())

    assert view.state is VolumeState.UNMOUNTED_BY_USER
    assert view.path == GAMES_PATH


def test_auto_record_of_an_unplugged_stick_is_not_present(ctx, runtime):
    _write_record(ctx, InstanceKind.AUTO, "sdc1-8_33", _games_record())

    (view,) = compute_views(ctx, _registry(), _tree(), ())

    assert view.state is VolumeState.NOT_PRESENT
    assert view.present is False
    assert view.uuid == ""


def test_auto_record_whose_kname_now_has_another_device_number_is_not_present(
    ctx, runtime
):
    _write_record(ctx, InstanceKind.AUTO, "sdc1-8_33", _games_record())
    games = _tree(TREE_WITH_GAMES).devices["sdc1"]
    moved = DeviceTree(
        devices={"sdc1": dataclasses.replace(games, devnum="8:49")},
        parents={"sdc1": ()},
    )

    (view,) = compute_views(ctx, _registry(), moved, ())

    assert view.state is VolumeState.NOT_PRESENT


def test_i006_record_renders_not_mounted_with_its_own_next_step(ctx, runtime):
    step = f"Run {CLI} mount --device /dev/sdb1."
    _write_record(
        ctx,
        InstanceKind.AUTO,
        "dm-0-252_0",
        _auto(
            "dm-0-252_0",
            name="PERSONAL",
            state="NotMounted",
            reason="no_partition_instance",
            warning=None,
            next_step=step,
            source=None,
            mount=None,
        ),
    )

    (view,) = compute_views(ctx, _registry(), _tree(), ())

    assert view.state is VolumeState.NOT_MOUNTED
    assert view.reason == "no_partition_instance"
    assert view.present is True
    assert view.path is None
    assert view.uuid == "88D48067D48058F8"
    assert view.next_step == step


def test_locked_auto_record(ctx, runtime):
    _write_record(
        ctx,
        InstanceKind.AUTO,
        "sdb1-8_17",
        _auto(
            "sdb1-8_17",
            name="PAT4T4SHUAWEI PERSONAL 4_3_2024",
            state="Locked",
            reason=None,
            warning=None,
            next_step=None,
            mount=None,
        ),
    )

    (view,) = compute_views(
        ctx, _registry(), _tree("lsblk-tree-personal-locked.json"), ()
    )

    assert view.state is VolumeState.LOCKED
    assert view.next_step == "Unlock it in Dolphin; it mounts by itself after that."


def test_views_list_registered_by_name_then_auto_by_path(ctx, runtime):
    _write_record(ctx, InstanceKind.AUTO, "sdc1-8_33", _games_record())
    _write_record(
        ctx,
        InstanceKind.AUTO,
        "sdb5-8_21",
        _games_record(
            "sdb5-8_21", name="ARCHIVE", mount={"target": "/run/media/deck/ARCHIVE"}
        ),
    )
    _write_record(
        ctx,
        InstanceKind.AUTO,
        "dm-0-252_0",
        _auto("dm-0-252_0", name="LOCKED-NO-PATH", state="NotMounted", mount=None),
    )
    zulu = RegistryVolume(
        name="ZULU", uuid="AAAA-BBBB", path="/run/media/deck/ZULU", fstype="vfat"
    )

    views = compute_views(
        ctx, _registry(zulu, PERSONAL, MEDIABOX), _tree(TREE_WITH_GAMES), ()
    )

    assert [(view.kind.value, view.name) for view in views] == [
        ("registered", "MEDIABOX"),
        ("registered", "PERSONAL"),
        ("registered", "ZULU"),
        ("auto", "LOCKED-NO-PATH"),
        ("auto", "ARCHIVE"),
        ("auto", "GAMES"),
    ]


def test_unreadable_and_foreign_files_in_the_auto_directory_are_skipped(ctx, runtime):
    auto = runtime / "records" / "auto"
    (auto / "sdc1-8_33.json").write_bytes(b"{")
    (auto / "notes.txt").write_text("x", encoding="utf-8")
    (auto / "Bad Key.json").write_text("{}", encoding="utf-8")
    (auto / ".sdc1-8_33.json.tmp").write_text("{}", encoding="utf-8")

    assert compute_views(ctx, _registry(), _tree(TREE_WITH_GAMES), ()) == []


def test_non_root_list_on_a_fresh_boot_has_no_records(ctx_deck, run_dir):
    (view,) = compute_views(ctx_deck, _registry(MEDIABOX), _tree(), ())

    assert view.state is VolumeState.NOT_MOUNTED


def test_compute_views_never_writes(ctx, runtime):
    path = _write_record(
        ctx,
        InstanceKind.REGISTERED,
        MEDIABOX_KEY,
        _registered(MEDIABOX_KEY, name="MEDIABOX", state="MountedRW"),
    )
    before = path.read_bytes()
    listing = sorted(str(p) for p in runtime.rglob("*"))

    compute_views(ctx, _registry(MEDIABOX), _tree(), ())

    assert path.read_bytes() == before
    assert sorted(str(p) for p in runtime.rglob("*")) == listing


def test_a_mount_at_the_path_without_a_device_in_the_tree_still_counts(ctx, runtime):
    lone = DeviceTree(devices={}, parents={})

    (view,) = compute_views(
        ctx, _registry(MEDIABOX), lone, _findmnt("findmnt-mediabox-fuseblk-rw.json")
    )

    assert view.state is VolumeState.MOUNTED_RW
    assert view.present is False


def test_registered_device_mounted_elsewhere_without_a_crypt_child(ctx, runtime):
    tree = parse_lsblk_json(
        json.dumps(
            {
                "blockdevices": [
                    lsblk_device(
                        "sdb5",
                        {
                            "fstype": "ntfs",
                            "uuid": "01D95F1575592A30",
                            "maj:min": "8:21",
                        },
                    )
                ]
            }
        ).encode()
    )
    elsewhere = MountInfo(
        target="/mnt/other",
        source="/dev/sdb5",
        fstype="ntfs3",
        vfs_options=("rw",),
        fs_options=("rw",),
        devnum="8:21",
    )

    (view,) = compute_views(ctx, _registry(MEDIABOX), tree, (elsewhere,))

    assert view.state is VolumeState.MOUNTED_ELSEWHERE
    assert (view.path, view.driver, view.mode) == ("/mnt/other", "ntfs3", "rw")


# --- words, next steps and warnings ---------------------------------------------------


WORDS = {
    VolumeState.NOT_PRESENT: "not present",
    VolumeState.NOT_MOUNTED: "present, not mounted yet",
    VolumeState.LOCKED: "locked and skipped",
    VolumeState.NEEDS_KEY: "needs a key",
    VolumeState.UNLOCK_FAILED: "unlock failed",
    VolumeState.UNLOCK_CANCELLED: "unlock cancelled at the key dialog",
    VolumeState.MOUNTING: "mounting",
    VolumeState.MOUNTED_RW: "mounted read-write",
    VolumeState.MOUNTED_RW_DIRTY: "mounted read-write via ntfs-3g (dirty)",
    VolumeState.MOUNTED_RO: "mounted read-only",
    VolumeState.MOUNTED_ELSEWHERE: "mounted elsewhere",
    VolumeState.MOUNT_FAILED: "mount failed",
    VolumeState.MOUNT_TIMED_OUT: "mount timed out",
    VolumeState.UNMOUNTED_BY_USER: "unmounted by the user",
}


@pytest.mark.parametrize(("volume_state", "expected"), WORDS.items())
def test_words_from_the_design_table(volume_state, expected):
    assert words(volume_state, None) == expected


def test_every_state_has_words():
    assert set(WORDS) == set(VolumeState)


@pytest.mark.parametrize(
    ("volume_state", "reason", "expected"),
    [
        (VolumeState.NEEDS_KEY, "no_session", "needs a key"),
        (VolumeState.NEEDS_KEY, "dialog_open", "needs a key: key dialog open"),
        (
            VolumeState.NEEDS_KEY,
            "dialog_failed",
            "needs a key: key dialog could not be shown",
        ),
        (
            VolumeState.NEEDS_KEY,
            "key_permissions",
            "needs a key: key file permissions",
        ),
        (
            VolumeState.UNLOCK_CANCELLED,
            "dialog_timed_out",
            "unlock cancelled at the key dialog: key dialog timed out",
        ),
        (VolumeState.MOUNTED_RO, "unsafe", f"mounted read-only: {UNSAFE_PHRASE}"),
        (VolumeState.MOUNT_FAILED, "device_busy", "mount failed: device busy"),
        (VolumeState.MOUNT_FAILED, "some tool message", "mount failed"),
        (
            VolumeState.NOT_PRESENT,
            "record_unreadable",
            "not present: its state record was unreadable",
        ),
        (
            VolumeState.NOT_MOUNTED,
            "record_unreadable",
            "present, not mounted yet: its state record was unreadable",
        ),
    ],
)
def test_words_with_a_reason(volume_state, reason, expected):
    assert words(volume_state, reason) == expected


NEXT_STEPS = [
    (VolumeState.NOT_PRESENT, None, "Plug the drive in."),
    (
        VolumeState.NOT_PRESENT,
        "record_unreadable",
        "Plug the drive in; journalctl -t steamos-mounter SM_VOLUME=DRIVE shows"
        " what was unmounted.",
    ),
    (VolumeState.NOT_MOUNTED, None, f"Run {CLI} mount --volume DRIVE."),
    (
        VolumeState.NOT_MOUNTED,
        "record_unreadable",
        f"Run {CLI} mount --volume DRIVE; journalctl -t steamos-mounter"
        " SM_VOLUME=DRIVE shows what was unmounted.",
    ),
    (
        VolumeState.LOCKED,
        None,
        "Unlock it in Dolphin; it mounts by itself after that.",
    ),
    (
        VolumeState.NEEDS_KEY,
        "no_session",
        f"In Desktop Mode, replug the drive or run {CLI} mount --volume DRIVE."
        f" Or run {CLI} set-key DRIVE.",
    ),
    (
        VolumeState.NEEDS_KEY,
        "dialog_open",
        "Answer the key dialog on the Deck's screen.",
    ),
    (
        VolumeState.NEEDS_KEY,
        "dialog_failed",
        f"Run {CLI} set-key DRIVE, or unlock it in Dolphin.",
    ),
    (
        VolumeState.NEEDS_KEY,
        "key_permissions",
        f"Run {CLI} doctor, then {CLI} set-key DRIVE.",
    ),
    (
        VolumeState.UNLOCK_FAILED,
        None,
        f"Replug the drive or run {CLI} mount --volume DRIVE to try again,"
        f" or run {CLI} set-key DRIVE.",
    ),
    (
        VolumeState.UNLOCK_CANCELLED,
        None,
        f"Replug the drive or run {CLI} mount --volume DRIVE when you want to"
        " unlock it.",
    ),
    (VolumeState.MOUNTING, None, "Wait a few seconds and run list again."),
    (VolumeState.MOUNTED_RW, None, "-"),
    (VolumeState.MOUNTED_RW_DIRTY, "dirty", "Run chkdsk /f on it in Windows."),
    (
        VolumeState.MOUNTED_RO,
        "unsafe",
        "Shut Windows down fully (no Fast Startup), then run chkdsk /f on it in"
        " Windows.",
    ),
    (
        VolumeState.MOUNTED_RO,
        None,
        "See journalctl -t steamos-mounter SM_VOLUME=DRIVE.",
    ),
    (
        VolumeState.MOUNTED_ELSEWHERE,
        None,
        f"Unmount it there, then run {CLI} mount --volume DRIVE to use the fixed path.",
    ),
    (
        VolumeState.MOUNT_FAILED,
        "fstype_mismatch",
        "Check that this is the right drive.",
    ),
    (
        VolumeState.MOUNT_FAILED,
        "device_busy",
        f"Wait, then run {CLI} mount --volume DRIVE.",
    ),
    (
        VolumeState.MOUNT_FAILED,
        None,
        f"See the journal, then run {CLI} mount --volume DRIVE.",
    ),
    (
        VolumeState.MOUNT_TIMED_OUT,
        None,
        f"Run {CLI} mount --volume DRIVE to try again.",
    ),
    (
        VolumeState.UNMOUNTED_BY_USER,
        None,
        f"Run {CLI} mount --volume DRIVE, or replug the drive.",
    ),
]


@pytest.mark.parametrize(("volume_state", "reason", "expected"), NEXT_STEPS)
def test_next_step_from_the_design_table(volume_state, reason, expected):
    assert next_step(volume_state, reason, name="DRIVE", cli_root=CLI) == expected


# Every NeedsKey and MountFailed reason the Design Doc names.
NEEDS_KEY_REASONS = (
    "stored_key_missing",
    "stored_key_rejected",
    "no_session",
    "session_not_sure",
    "dialog_open",
    "dialog_failed",
    "key_permissions",
)
MOUNT_FAILED_REASONS = (
    "fstype_mismatch",
    "device_busy",
    "no_free_name",
    "probe_failed",
    "registry_entry_invalid",
    "os_partition",
    "unknown",
)


@pytest.mark.parametrize("reason", NEEDS_KEY_REASONS)
def test_every_needs_key_reason_has_a_step_naming_the_volume_or_the_dialog(reason):
    step = next_step(VolumeState.NEEDS_KEY, reason, name="DRIVE", cli_root=CLI)

    assert step.endswith(".")
    assert "DRIVE" in step or "key dialog" in step


@pytest.mark.parametrize("reason", MOUNT_FAILED_REASONS)
def test_every_mount_failed_reason_has_a_step(reason):
    step = next_step(VolumeState.MOUNT_FAILED, reason, name="DRIVE", cli_root=CLI)

    assert step.endswith(".")
    assert step != "-"


@pytest.mark.parametrize("reason", ["stored_key_missing", "session_not_sure"])
def test_key_reasons_without_a_dialog_use_the_no_session_step(reason):
    expected = next_step(VolumeState.NEEDS_KEY, "no_session", name="D", cli_root=CLI)

    assert next_step(VolumeState.NEEDS_KEY, reason, name="D", cli_root=CLI) == expected


def test_unknown_reason_falls_back_to_the_states_step():
    assert next_step(
        VolumeState.MOUNT_FAILED, "mount: wrong fs type", name="D", cli_root=CLI
    ) == next_step(VolumeState.MOUNT_FAILED, None, name="D", cli_root=CLI)


def test_cli_root_comes_from_the_caller():
    step = next_step(VolumeState.NOT_MOUNTED, None, name="D", cli_root="sudo /x/sm")

    assert step == "Run sudo /x/sm mount --volume D."


def test_braces_in_a_name_are_text_not_placeholders():
    step = next_step(VolumeState.NOT_MOUNTED, None, name="{cli}{0}", cli_root=CLI)

    assert step == f"Run {CLI} mount --volume {{cli}}{{0}}."


def test_next_step_table_has_no_duplicated_text():
    texts = [text for text in state.NEXT_STEP_TEXTS.values() if text != "-"]

    assert len(texts) == len(set(texts))


def test_unsafe_wording():
    warning = state.warning(VolumeState.MOUNTED_RO, "unsafe", name="MEDIABOX")
    step = next_step(VolumeState.MOUNTED_RO, "unsafe", name="MEDIABOX", cli_root=CLI)

    assert warning is not None
    assert warning.startswith("MEDIABOX is in an " + UNSAFE_PHRASE)
    assert "read-only" in warning
    assert "hibernated" not in warning
    assert UNSAFE_PHRASE in words(VolumeState.MOUNTED_RO, "unsafe")
    assert "Shut Windows down fully" in step
    assert "chkdsk /f" in step


def test_dirty_warning_matches_the_record_schema_example():
    assert (
        state.warning(VolumeState.MOUNTED_RW_DIRTY, "dirty", name="PERSONAL")
        == DIRTY_WARNING
    )


@pytest.mark.parametrize(
    ("volume_state", "reason"),
    [(VolumeState.MOUNTED_RW, None), (VolumeState.MOUNTED_RO, None)],
)
def test_no_default_warning_without_a_known_cause(volume_state, reason):
    assert state.warning(volume_state, reason, name="D") is None
