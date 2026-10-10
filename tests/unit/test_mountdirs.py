"""mountdirs: fixed-path rule 8, trusted parent directories, on the host tree.

Owner decision of 2026-10-10 (option A, closing the mount-target race): every
directory from ``/`` through the target's parent must be a real directory
(``lstat``, never a symlink), owned by root, with no group or other write
bit. ``prepare_target`` checks it right before every mount, for fixed paths
and for mount-base children alike.

The tree is real, under ``HostPaths(root=tmp_path)``. The tests do not run as
root, so ownership is injected through the facts seam: ``HostPathFacts`` and
``FakePlatform`` take the test uid as the trusted uid, and a different
``trusted_uid`` stands in for a directory ``deck`` owns. Modes are real
``chmod`` calls.
"""

import dataclasses
import os
from pathlib import Path

import pytest

from steamos_mounter.errors import RefusedError
from steamos_mounter.mountdirs import HostPathFacts, prepare_target
from steamos_mounter.naming import validate_fixed_path
from steamos_mounter.platforms.base import HostPaths

BASE = "/run/media/deck"
GAMES_TARGET = f"{BASE}/GAMES"
DRIVES = "/home/deck/Drives"
DRIVES_TARGET = f"{DRIVES}/GAMES"
DATA_TARGET = "/data/drives/GAMES"
UNTRUSTED_PARENT = "a parent directory is a symlink or writable by a non-root user"
# The uid a directory has when someone other than the trusted uid owns it.
OTHER_UID = os.getuid() + 1


def make_dir(root: Path, absolute: str, mode: int = 0o755) -> Path:
    """``absolute`` under ``root`` with ``mode``; missing parents get 0755."""
    path = root / absolute.lstrip("/")
    path.mkdir(parents=True, exist_ok=True)
    for parent in path.relative_to(root).parents:
        (root / parent).chmod(0o755)
    path.chmod(mode)
    return path


def deck_layout(root: Path) -> None:
    """``/run`` and ``/run/media`` root 0755, the mount base root 0750.

    On the Deck the base also has the ACL ``u:deck:r-x``; with an ACL the
    group bits of ``st_mode`` show the ACL mask (``r-x``), which 0750 models.
    """
    make_dir(root, "/run/media")
    make_dir(root, BASE, 0o750)


def facts(root: Path, trusted_uid: int | None = None) -> HostPathFacts:
    uid = os.getuid() if trusted_uid is None else trusted_uid
    return HostPathFacts(HostPaths(root=root), trusted_uid=uid)


# --- HostPathFacts.trusted_dir ---------------------------------------------------


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o700, 0o555], ids=oct)
def test_root_owned_directory_without_group_or_other_write_is_trusted(tmp_path, mode):
    make_dir(tmp_path, DRIVES, mode)

    assert facts(tmp_path).trusted_dir(DRIVES) is True


@pytest.mark.parametrize(
    "mode",
    [
        pytest.param(0o775, id="group-writable"),
        pytest.param(0o757, id="other-writable"),
        pytest.param(0o1777, id="sticky-world-writable"),
    ],
)
def test_root_owned_but_writable_directory_is_not_trusted(tmp_path, mode):
    make_dir(tmp_path, DRIVES, mode)

    assert facts(tmp_path).trusted_dir(DRIVES) is False


def test_directory_owned_by_another_user_is_not_trusted(tmp_path):
    make_dir(tmp_path, DRIVES)

    assert facts(tmp_path, trusted_uid=OTHER_UID).trusted_dir(DRIVES) is False


def test_symlink_to_a_trusted_directory_is_not_trusted(tmp_path):
    real = make_dir(tmp_path, "/real-drives")
    make_dir(tmp_path, "/home/deck")
    (tmp_path / DRIVES.lstrip("/")).symlink_to(real, target_is_directory=True)

    assert facts(tmp_path).trusted_dir("/real-drives") is True
    assert facts(tmp_path).trusted_dir(DRIVES) is False


@pytest.mark.parametrize("entry", ["missing", "file"])
def test_missing_path_or_file_is_not_a_trusted_directory(tmp_path, entry):
    make_dir(tmp_path, "/home/deck")
    if entry == "file":
        (tmp_path / DRIVES.lstrip("/")).write_text("")

    assert facts(tmp_path).trusted_dir(DRIVES) is False


# --- prepare_target: fixed paths ------------------------------------------------


def with_trusted_uid(ctx, uid: int):
    return dataclasses.replace(
        ctx, platform=dataclasses.replace(ctx.platform, trusted_uid=uid)
    )


def test_fixed_path_under_trusted_parents_is_created(ctx, tmp_path):
    deck_layout(tmp_path)
    make_dir(tmp_path, "/data/drives")

    assert prepare_target(ctx, DATA_TARGET) is True
    assert (tmp_path / DATA_TARGET.lstrip("/")).is_dir()


def test_fixed_path_under_a_deck_owned_parent_is_refused(ctx, tmp_path):
    deck_layout(tmp_path)
    make_dir(tmp_path, DRIVES)
    deck_owned = with_trusted_uid(ctx, OTHER_UID)

    with pytest.raises(RefusedError) as raised:
        prepare_target(deck_owned, DRIVES_TARGET)

    assert raised.value.user_message == UNTRUSTED_PARENT
    assert not (tmp_path / DRIVES_TARGET.lstrip("/")).exists()


@pytest.mark.parametrize(
    ("writable", "mode"),
    [
        pytest.param("/data/drives", 0o775, id="group-writable-parent"),
        pytest.param("/data/drives", 0o757, id="other-writable-parent"),
        pytest.param("/data", 0o777, id="world-writable-grandparent"),
    ],
)
def test_fixed_path_under_a_writable_parent_is_refused(ctx, tmp_path, writable, mode):
    deck_layout(tmp_path)
    make_dir(tmp_path, "/data/drives")
    (tmp_path / writable.lstrip("/")).chmod(mode)

    with pytest.raises(RefusedError, match=UNTRUSTED_PARENT):
        prepare_target(ctx, DATA_TARGET)

    assert not (tmp_path / DATA_TARGET.lstrip("/")).exists()


def test_fixed_path_under_a_symlinked_ancestor_is_refused(ctx, tmp_path):
    """Even when the link points at a trusted directory."""
    deck_layout(tmp_path)
    real = make_dir(tmp_path, "/real-data")
    make_dir(tmp_path, "/real-data/drives")
    (tmp_path / "data").symlink_to(real, target_is_directory=True)

    with pytest.raises(RefusedError, match=UNTRUSTED_PARENT):
        prepare_target(ctx, DATA_TARGET)

    assert not (tmp_path / "real-data/drives/GAMES").exists()


@pytest.mark.parametrize("change", ["chmod", "symlink"])
def test_fixed_path_is_refused_at_mount_time_when_a_parent_changed_after_add(
    ctx, tmp_path, change
):
    deck_layout(tmp_path)
    make_dir(tmp_path, "/data/drives")
    host_facts = HostPathFacts(ctx.paths, trusted_uid=ctx.platform.trusted_uid)
    validate_fixed_path(DATA_TARGET, mount_base=BASE, other_paths=(), fs=host_facts)
    if change == "chmod":
        (tmp_path / "data").chmod(0o777)
    else:
        (tmp_path / "data").rename(tmp_path / "moved")
        (tmp_path / "data").symlink_to(tmp_path / "moved", target_is_directory=True)

    with pytest.raises(RefusedError, match=UNTRUSTED_PARENT):
        prepare_target(ctx, DATA_TARGET)

    assert not (tmp_path / "moved/drives/GAMES").exists()
    assert not (tmp_path / DATA_TARGET.lstrip("/")).exists()


# --- prepare_target: mount-base children -----------------------------------------


def test_auto_target_under_the_deck_mount_base_layout_is_created(ctx, tmp_path):
    deck_layout(tmp_path)

    assert prepare_target(ctx, GAMES_TARGET) is True
    assert (tmp_path / GAMES_TARGET.lstrip("/")).is_dir()


@pytest.mark.parametrize(
    ("writable", "mode"),
    [
        pytest.param(BASE, 0o770, id="group-writable-base"),
        pytest.param("/run/media", 0o757, id="other-writable-media"),
    ],
)
def test_auto_target_under_a_writable_parent_is_refused(ctx, tmp_path, writable, mode):
    deck_layout(tmp_path)
    (tmp_path / writable.lstrip("/")).chmod(mode)

    with pytest.raises(RefusedError) as raised:
        prepare_target(ctx, GAMES_TARGET)

    assert raised.value.user_message == UNTRUSTED_PARENT
    assert raised.value.detail == (
        f"mount target {GAMES_TARGET!r} refused: {UNTRUSTED_PARENT}"
    )
    assert not (tmp_path / GAMES_TARGET.lstrip("/")).exists()


def test_auto_target_under_a_symlinked_run_is_refused(ctx, tmp_path):
    real = make_dir(tmp_path, "/real-run")
    make_dir(tmp_path, "/real-run/media")
    make_dir(tmp_path, "/real-run/media/deck", 0o750)
    (tmp_path / "run").symlink_to(real, target_is_directory=True)

    with pytest.raises(RefusedError, match=UNTRUSTED_PARENT):
        prepare_target(ctx, GAMES_TARGET)

    assert not (tmp_path / "real-run/media/deck/GAMES").exists()


def test_auto_target_when_root_does_not_own_the_base_is_refused(ctx, tmp_path):
    deck_layout(tmp_path)

    with pytest.raises(RefusedError, match=UNTRUSTED_PARENT):
        prepare_target(with_trusted_uid(ctx, OTHER_UID), GAMES_TARGET)
