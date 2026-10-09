"""Atomic writes, the symlink flip and the owner/mode check, on real files.

Design Doc "Registry > Atomic Write" and "Module Responsibilities > atomicfile";
ADR-0004 D3 item 4 and "Implementation Guidance" (one helper that creates a
file with its final mode, flushes it, renames it into place and flushes the
directory). Files are real files under ``tmp_path``; the owner is the test
uid, which is the only owner a non-root test can set.
"""

import os
import stat
from pathlib import Path

import pytest

from steamos_mounter.atomicfile import (
    OwnerModeProblem,
    check_owner_mode,
    replace_symlink,
    write_atomic,
)

UID = os.getuid()
GID = os.getgid()
IS_ROOT = UID == 0


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _leftovers(directory: Path, keep: set[str]) -> list[str]:
    return sorted(name for name in os.listdir(directory) if name not in keep)


# --- write_atomic ---------------------------------------------------------------------


def test_write_atomic_creates_the_file_with_data_mode_and_owner(tmp_path):
    target = tmp_path / "config.toml"

    write_atomic(target, b"schema_version = 1\n", mode=0o644, uid=UID, gid=GID)

    assert target.read_bytes() == b"schema_version = 1\n"
    assert _mode(target) == 0o644
    assert (os.stat(target).st_uid, os.stat(target).st_gid) == (UID, GID)
    assert _leftovers(tmp_path, {"config.toml"}) == []


def test_write_atomic_sets_a_private_mode_whatever_the_umask(tmp_path):
    target = tmp_path / "key"
    old_umask = os.umask(0)
    try:
        write_atomic(target, b"x", mode=0o600, uid=UID, gid=GID)
    finally:
        os.umask(old_umask)

    assert _mode(target) == 0o600


def test_write_atomic_replaces_an_existing_file_and_its_mode(tmp_path):
    target = tmp_path / "config.toml"
    target.write_bytes(b"old contents that are longer than the new ones\n")
    target.chmod(0o600)
    old_inode = os.stat(target).st_ino

    write_atomic(target, b"new\n", mode=0o644, uid=UID, gid=GID)

    assert target.read_bytes() == b"new\n"
    assert _mode(target) == 0o644
    assert os.stat(target).st_ino != old_inode  # renamed into place, not rewritten


def test_write_atomic_writes_empty_data(tmp_path):
    target = tmp_path / "empty"

    write_atomic(target, b"", mode=0o644, uid=UID, gid=GID)

    assert target.read_bytes() == b""


def test_write_atomic_temp_file_sits_in_the_target_directory(tmp_path, monkeypatch):
    target = tmp_path / "config.toml"
    seen: list[str] = []
    real_replace = os.replace

    def spy(source, destination):
        seen.append(os.fspath(source))
        real_replace(source, destination)

    monkeypatch.setattr(os, "replace", spy)

    write_atomic(target, b"x", mode=0o644, uid=UID, gid=GID)

    assert len(seen) == 1
    assert os.path.dirname(seen[0]) == str(tmp_path)
    assert os.path.basename(seen[0]).startswith(".config.toml.")


def test_write_atomic_unlinks_the_temp_file_when_the_rename_fails(tmp_path):
    target = tmp_path / "config.toml"
    target.mkdir()  # rename of a file over a directory fails

    with pytest.raises(IsADirectoryError):
        write_atomic(target, b"x", mode=0o644, uid=UID, gid=GID)

    assert _leftovers(tmp_path, {"config.toml"}) == []
    assert target.is_dir()


@pytest.mark.skipif(IS_ROOT, reason="root may give a file to any owner")
def test_write_atomic_unlinks_the_temp_file_when_chown_is_refused(tmp_path):
    target = tmp_path / "config.toml"
    target.write_bytes(b"keep me\n")

    with pytest.raises(PermissionError):
        write_atomic(target, b"x", mode=0o644, uid=0, gid=0)

    assert target.read_bytes() == b"keep me\n"
    assert _leftovers(tmp_path, {"config.toml"}) == []


def test_write_atomic_fails_when_the_directory_is_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        write_atomic(tmp_path / "missing" / "f", b"x", mode=0o644, uid=UID, gid=GID)


# --- replace_symlink ------------------------------------------------------------------


def test_replace_symlink_creates_a_new_link(tmp_path):
    link = tmp_path / "current"

    replace_symlink(link, "releases/0.1.0")

    assert os.readlink(link) == "releases/0.1.0"
    assert _leftovers(tmp_path, {"current"}) == []


def test_replace_symlink_flips_an_existing_link_in_one_rename(tmp_path):
    link = tmp_path / "current"
    link.symlink_to("releases/0.1.0")

    replace_symlink(link, "releases/0.2.0")

    assert os.readlink(link) == "releases/0.2.0"
    assert _leftovers(tmp_path, {"current"}) == []


def test_replace_symlink_retries_a_taken_temporary_name(tmp_path, monkeypatch):
    link = tmp_path / "current"
    names = iter(["taken", "free"])
    monkeypatch.setattr(
        "steamos_mounter.atomicfile.secrets.token_hex", lambda _n: next(names)
    )
    (tmp_path / ".current.taken").write_text("someone else's\n")

    replace_symlink(link, "releases/0.3.0")

    assert os.readlink(link) == "releases/0.3.0"
    assert (tmp_path / ".current.taken").read_text() == "someone else's\n"


def test_replace_symlink_gives_up_when_no_temporary_name_is_free(tmp_path, monkeypatch):
    link = tmp_path / "current"
    monkeypatch.setattr(
        "steamos_mounter.atomicfile.secrets.token_hex", lambda _n: "taken"
    )
    (tmp_path / ".current.taken").write_text("someone else's\n")

    with pytest.raises(FileExistsError):
        replace_symlink(link, "releases/0.3.0")

    assert not link.exists()
    assert _leftovers(tmp_path, set()) == [".current.taken"]


def test_replace_symlink_removes_its_temporary_link_on_failure(tmp_path):
    link = tmp_path / "current"
    link.mkdir()
    (link / "child").write_text("x")  # a non-empty directory cannot be replaced

    with pytest.raises(OSError):
        replace_symlink(link, "releases/0.1.0")

    assert _leftovers(tmp_path, {"current"}) == []
    assert link.is_dir()


# --- check_owner_mode -----------------------------------------------------------------


def test_check_owner_mode_accepts_a_good_file(tmp_path):
    path = tmp_path / "f"
    path.write_text("x")
    path.chmod(0o644)

    assert check_owner_mode(path, uid=UID, forbid=0o022, kind="file") is None


def test_check_owner_mode_accepts_a_good_directory(tmp_path):
    path = tmp_path / "d"
    path.mkdir(mode=0o755)
    path.chmod(0o755)

    assert check_owner_mode(path, uid=UID, forbid=0o022, kind="dir") is None


@pytest.mark.parametrize(
    ("mode", "problem"),
    [
        (0o664, "mode 0o664 has forbidden bits 0o20"),
        (0o646, "mode 0o646 has forbidden bits 0o2"),
        (0o666, "mode 0o666 has forbidden bits 0o22"),
    ],
)
def test_check_owner_mode_reports_forbidden_bits(tmp_path, mode, problem):
    path = tmp_path / "f"
    path.write_text("x")
    path.chmod(mode)

    assert check_owner_mode(path, uid=UID, forbid=0o022, kind="file") == (
        OwnerModeProblem(path=str(path), problem=problem)
    )


def test_check_owner_mode_with_a_wider_forbid_mask(tmp_path):
    path = tmp_path / "key"
    path.write_text("x")
    path.chmod(0o640)

    problem = check_owner_mode(path, uid=UID, forbid=0o077, kind="file")

    assert problem == OwnerModeProblem(str(path), "mode 0o640 has forbidden bits 0o40")


def test_check_owner_mode_reports_a_foreign_owner(tmp_path):
    path = tmp_path / "f"
    path.write_text("x")
    path.chmod(0o644)

    problem = check_owner_mode(path, uid=UID + 1, forbid=0o022, kind="file")

    assert problem == OwnerModeProblem(str(path), f"owned by uid {UID}, not {UID + 1}")


@pytest.mark.parametrize("kind", ["file", "dir"])
def test_check_owner_mode_refuses_a_symlink(tmp_path, kind):
    real = tmp_path / "real"
    if kind == "dir":
        real.mkdir()
    else:
        real.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(real)

    problem = check_owner_mode(link, uid=UID, forbid=0o022, kind=kind)

    assert problem == OwnerModeProblem(str(link), "is a symlink")


def test_check_owner_mode_refuses_a_directory_where_a_file_belongs(tmp_path):
    path = tmp_path / "d"
    path.mkdir()

    problem = check_owner_mode(path, uid=UID, forbid=0o022, kind="file")

    assert problem == OwnerModeProblem(str(path), "is not a regular file")


def test_check_owner_mode_refuses_a_file_where_a_directory_belongs(tmp_path):
    path = tmp_path / "f"
    path.write_text("x")

    problem = check_owner_mode(path, uid=UID, forbid=0o022, kind="dir")

    assert problem == OwnerModeProblem(str(path), "is not a directory")


def test_check_owner_mode_reports_a_missing_path(tmp_path):
    path = tmp_path / "missing"

    problem = check_owner_mode(path, uid=UID, forbid=0o022, kind="file")

    assert problem == OwnerModeProblem(str(path), "is missing")


def test_check_owner_mode_reports_a_path_it_cannot_inspect(tmp_path):
    path = tmp_path / "file" / "below-a-file"
    (tmp_path / "file").write_text("x")

    problem = check_owner_mode(path, uid=UID, forbid=0o022, kind="file")

    assert problem == OwnerModeProblem(
        str(path), "cannot be inspected: Not a directory"
    )
