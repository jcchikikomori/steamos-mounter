"""The four locks, with real ``flock`` in ``tmp_path``.

Design Doc "Locks" and "Module Responsibilities > locks"; "Mock Boundary
Decisions": ``flock`` is never mocked, because the race tests need real
locking. Two holders in one process conflict because each lock opens its own
file description. Timeouts are real seconds, kept short.
"""

import inspect
import logging
import os
import stat
import threading
from pathlib import Path

import pytest

from steamos_mounter import locks
from steamos_mounter.errors import MounterError
from steamos_mounter.locks import (
    LockTimeout,
    automount_lock,
    dialog_lock,
    registry_lock,
    volume_lock,
)

SHORT = 0.1
LONG = 5.0
LOCKS_DIR = "run/steamos-mounter/locks"
HOLO_DIR = "var/run"


@pytest.fixture
def locks_dir(tmp_path: Path) -> Path:
    """The 0700 ``locks/`` directory ``records.ensure_runtime_dirs`` provides."""
    directory = tmp_path / LOCKS_DIR
    directory.mkdir(parents=True)
    directory.chmod(0o700)
    return directory


@pytest.fixture
def holo_dir(tmp_path: Path) -> Path:
    directory = tmp_path / HOLO_DIR
    directory.mkdir(parents=True)
    return directory


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


# --- lock files -----------------------------------------------------------------------


def test_volume_lock_file_is_named_by_the_lowercased_key(ctx, locks_dir):
    with volume_lock(ctx, "01D95F1575592A30", timeout=SHORT):
        path = locks_dir / "volume-01d95f1575592a30.lock"
        assert path.is_file()
        assert _mode(path) == 0o600


def test_volume_lock_takes_a_device_record_key(ctx, locks_dir):
    with volume_lock(ctx, "sdc1-8_33", timeout=SHORT):
        assert (locks_dir / "volume-sdc1-8_33.lock").is_file()


def test_registry_and_dialog_lock_files(ctx, locks_dir):
    with registry_lock(ctx, timeout=SHORT), dialog_lock(ctx, timeout=SHORT):
        assert sorted(os.listdir(locks_dir)) == ["dialog.lock", "registry.lock"]


def test_lock_file_is_kept_after_release(ctx, locks_dir):
    with registry_lock(ctx, timeout=SHORT):
        pass

    assert (locks_dir / "registry.lock").is_file()


@pytest.mark.parametrize("key", ["", "../registry", "a/b", "-x", "A B", "x" * 129])
def test_volume_lock_refuses_a_key_that_is_not_a_safe_file_name(ctx, locks_dir, key):
    with (
        pytest.raises(ValueError, match="lock key"),
        volume_lock(ctx, key, timeout=SHORT),
    ):
        pass

    assert os.listdir(locks_dir) == []


def test_lock_without_the_locks_directory_fails_closed(ctx):
    with (
        pytest.raises(MounterError) as raised,
        registry_lock(ctx, timeout=SHORT),
    ):
        pass

    assert "registry.lock" in raised.value.detail


def test_lock_refuses_a_symlinked_lock_file(ctx, locks_dir, tmp_path):
    (locks_dir / "registry.lock").symlink_to(tmp_path / "elsewhere")

    with pytest.raises(MounterError), registry_lock(ctx, timeout=SHORT):
        pass

    assert not (tmp_path / "elsewhere").exists()


# --- exclusion and timeouts -----------------------------------------------------------


def test_second_holder_of_the_same_volume_times_out(ctx, locks_dir):
    with (
        volume_lock(ctx, "C40C-B21F", timeout=SHORT),
        pytest.raises(LockTimeout) as raised,
        volume_lock(ctx, "c40c-b21f", timeout=SHORT),
    ):
        pass

    assert raised.value.exit_code == 1
    assert "volume-c40c-b21f.lock" in raised.value.detail


def test_different_volumes_do_not_block_each_other(ctx, locks_dir):
    with (
        volume_lock(ctx, "C40C-B21F", timeout=SHORT),
        volume_lock(ctx, "01D95F1575592A30", timeout=SHORT),
    ):
        pass


def test_zero_timeout_tries_exactly_once(ctx, locks_dir):
    with (
        registry_lock(ctx, timeout=SHORT),
        pytest.raises(LockTimeout),
        registry_lock(ctx, timeout=0),
    ):
        pass


def test_lock_is_free_again_after_the_holder_leaves(ctx, locks_dir):
    with dialog_lock(ctx, timeout=SHORT):
        pass

    with dialog_lock(ctx, timeout=0):
        pass


def test_lock_is_released_when_the_body_raises(ctx, locks_dir):
    with pytest.raises(RuntimeError), volume_lock(ctx, "C40C-B21F", timeout=SHORT):
        raise RuntimeError("body failed")

    with volume_lock(ctx, "C40C-B21F", timeout=0):
        pass


def test_waiter_gets_the_lock_once_the_holder_releases(ctx, locks_dir):
    held = threading.Event()
    release = threading.Event()
    order: list[str] = []

    def holder() -> None:
        with volume_lock(ctx, "C40C-B21F", timeout=SHORT):
            order.append("holder in")
            held.set()
            release.wait(LONG)
            order.append("holder out")

    thread = threading.Thread(target=holder)
    thread.start()
    assert held.wait(LONG)
    threading.Timer(0.2, release.set).start()

    with volume_lock(ctx, "C40C-B21F", timeout=LONG):
        order.append("waiter in")
    thread.join(LONG)

    assert order == ["holder in", "holder out", "waiter in"]


def test_lock_timeout_is_a_mounter_error_with_a_generic_message(ctx, locks_dir):
    with (
        registry_lock(ctx, timeout=SHORT),
        pytest.raises(LockTimeout) as raised,
        registry_lock(ctx, timeout=SHORT),
    ):
        pass

    assert isinstance(raised.value, MounterError)
    assert str(raised.value) == "another steamos-mounter operation is still running"


# --- holo's per-device lock -----------------------------------------------------------


def test_automount_lock_takes_holos_lock_for_a_partition(ctx, holo_dir):
    with automount_lock(ctx, "sdb1", timeout=SHORT) as taken:
        assert taken is True
        assert (holo_dir / "jupiter-automount-sdb1.lock").is_file()


@pytest.mark.parametrize("kname", ["dm-0", "dm-12", "sdB1", "nvme0n1p8-x", ""])
def test_automount_lock_is_skipped_for_names_holo_cannot_build(ctx, holo_dir, kname):
    with automount_lock(ctx, kname, timeout=SHORT) as taken:
        assert taken is False

    assert os.listdir(holo_dir) == []


def test_automount_lock_is_skipped_with_debug_when_var_run_is_missing(ctx, caplog):
    caplog.set_level(logging.DEBUG, logger="steamos_mounter.locks")

    with automount_lock(ctx, "sdb1", timeout=SHORT) as taken:
        assert taken is False

    debug = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert len(debug) == 1
    assert "jupiter-automount-sdb1.lock" in debug[0].getMessage()


def test_automount_lock_is_skipped_when_var_run_is_not_a_directory(ctx, tmp_path):
    (tmp_path / "var").mkdir()
    (tmp_path / HOLO_DIR).write_text("not a directory\n")

    with automount_lock(ctx, "mmcblk0p1", timeout=SHORT) as taken:
        assert taken is False


def test_automount_lock_busy_raises_lock_timeout(ctx, holo_dir):
    with (
        automount_lock(ctx, "sdb1", timeout=SHORT),
        pytest.raises(LockTimeout),
        automount_lock(ctx, "sdb1", timeout=SHORT),
    ):
        pass


@pytest.mark.parametrize(
    ("lock", "seconds"), [(locks.automount_lock, 5.0), (locks.registry_lock, 10.0)]
)
def test_default_waits_follow_the_locks_table(lock, seconds):
    assert inspect.signature(lock).parameters["timeout"].default == seconds
