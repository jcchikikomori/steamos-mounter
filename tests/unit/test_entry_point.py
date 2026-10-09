"""Unit tests for the entry point ``bin/steamos-mounter``.

Design Doc: docs/design/steamos-mounter-design.md (sections "Entry Point
bin/steamos-mounter (Authoritative)", DD-04, DD-30, "Design-level Criteria
(EARS) > Entry, Verbs and Guards" and "Required Specific Tests", entry-point
trust: D003, D004, I009). ADR-0004: releases live under
/opt/steamos-mounter/releases/<version>/ and are reached through ``current``.

The script has no ``.py`` suffix, so it is loaded by path with
``SourceFileLoader``. Trees are real temporary directories with real modes and
real symlinks. The test user is not root, so the owner check is faked at the
``os.lstat`` boundary: every entry reports uid 0 unless the test names it as
foreign. ``steamos_mounter.cli`` is a stand-in module until the CLI lands.
"""

import importlib.machinery
import importlib.util
import os
import stat
import sys
import types
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest

from tests.contract.test_python import foreign_imports

REPO = Path(__file__).resolve().parents[2]
ENTRY_POINT = REPO / "bin" / "steamos-mounter"
SHEBANG = "#!/usr/bin/python3 -I"

DIR_MODE = 0o755
FILE_MODE = 0o644
DECK_UID = 1000
CLI_EXIT = 7

PLATFORM_LINE = "steamos-mounter: unsupported platform: SteamOS only.\n"
REFUSAL_LINE = (
    "steamos-mounter: refusing to run as root outside a root-owned release in"
    " /opt/steamos-mounter. Reinstall with sudo ./install.sh.\n"
)

# A release as the installer lays it out: bin/, lib/<package>, units.
RELEASE_FILES = (
    "bin/steamos-mounter",
    "lib/steamos_mounter/__init__.py",
    "lib/steamos_mounter/cli.py",
    "units/steamos-mounter@.service",
    "manifest",
)


def load_entry_point(path: Path = ENTRY_POINT) -> types.ModuleType:
    """Execute the script at ``path`` as a fresh module, without bytecode."""
    loader = importlib.machinery.SourceFileLoader("steamos_mounter_entry", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def build_release(root: Path, files: Iterable[str] = RELEASE_FILES) -> Path:
    """Create ``files`` under ``root`` with release modes (dirs 0755, files 0644)."""
    root.mkdir(parents=True)
    for relative in files:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# release file\n", encoding="utf-8")
    for path in [root, *root.rglob("*")]:
        if not path.is_symlink():
            path.chmod(DIR_MODE if path.is_dir() else FILE_MODE)
    return root


def owner_faking_lstat(foreign: Iterable[Path] = ()) -> Callable[..., os.stat_result]:
    """``os.lstat`` that reports uid 0, or ``DECK_UID`` for the ``foreign`` paths."""
    real_lstat = os.lstat
    foreign_paths = {os.fspath(path) for path in foreign}

    def lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        fields = list(info)
        fields[stat.ST_UID] = DECK_UID if os.fspath(path) in foreign_paths else 0
        return os.stat_result(fields)

    return lstat


def walk_removing(victim: Path) -> Callable[..., Iterable]:
    """``os.walk`` that deletes ``victim`` after listing its directory."""
    real_walk = os.walk

    def walk(top, *args, **kwargs):
        for dirpath, dirnames, filenames in real_walk(top, *args, **kwargs):
            if Path(dirpath) == victim.parent:
                if victim.is_dir():
                    victim.rmdir()
                else:
                    victim.unlink()
            yield dirpath, dirnames, filenames

    return walk


def lstat_removing_dir(victim: Path) -> Callable[..., os.stat_result]:
    """Current ``os.lstat`` that removes the empty ``victim`` once it is measured.

    The walk lists the directory, the trust check ``lstat``s it, and only then
    does the walk ``scandir`` it: the window between the two is reproduced
    exactly, with no timing involved.
    """
    inner_lstat = os.lstat
    victim_path = os.fspath(victim)

    def lstat(path, *args, **kwargs):
        info = inner_lstat(path, *args, **kwargs)
        if os.fspath(path) == victim_path:
            os.rmdir(victim_path)
        return info

    return lstat


def write_os_release(path: Path, os_id: str) -> Path:
    path.write_text(f'NAME="Some OS"\nID={os_id}\nVERSION_ID=1\n', encoding="utf-8")
    return path


@pytest.fixture
def entry() -> types.ModuleType:
    return load_entry_point()


@pytest.fixture
def root_owner(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    """Treat the test user's files as root-owned, except the paths passed in."""

    def install(*foreign: Path) -> None:
        monkeypatch.setattr(os, "lstat", owner_faking_lstat(foreign))

    return install


@pytest.fixture
def cli_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[list[str], str]]:
    """Stand-in ``steamos_mounter.cli`` recording each ``main`` call."""
    calls: list[tuple[list[str], str]] = []

    def main(argv: list[str], *, release_root: str) -> int:
        calls.append((argv, release_root))
        return CLI_EXIT

    stand_in = types.ModuleType("steamos_mounter.cli")
    stand_in.main = main
    monkeypatch.setitem(sys.modules, "steamos_mounter.cli", stand_in)
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "argv", ["steamos-mounter", "list", "--json"])
    return calls


@pytest.fixture
def host(
    entry: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Callable[..., None]:
    """Configure euid, the os-release ID and the release root for ``main``."""

    def configure(*, euid: int, os_id: str, root: Path | str) -> None:
        os_release = write_os_release(tmp_path / "os-release", os_id)
        monkeypatch.setattr(entry, "OS_RELEASE", str(os_release))
        monkeypatch.setattr(os, "geteuid", lambda: euid)
        monkeypatch.setattr(entry, "release_root", lambda: os.fspath(root))

    return configure


@pytest.fixture
def releases_dir(entry: types.ModuleType, monkeypatch, tmp_path: Path) -> Path:
    """A temporary stand-in for /opt/steamos-mounter/releases/."""
    releases = tmp_path / "opt" / "steamos-mounter" / "releases"
    releases.mkdir(parents=True)
    monkeypatch.setattr(entry, "RELEASES_DIR", f"{releases}/")
    return releases


# --- the file itself -------------------------------------------------------


def test_entry_point_is_executable_and_runs_isolated_python():
    first_line = ENTRY_POINT.read_text(encoding="utf-8").splitlines()[0]

    assert first_line == SHEBANG
    assert stat.S_IMODE(ENTRY_POINT.stat().st_mode) == 0o755


def test_entry_point_imports_only_stdlib_and_the_package():
    assert foreign_imports(ENTRY_POINT.read_text(encoding="utf-8")) == set()


def test_releases_dir_is_the_opt_release_tree_with_a_trailing_slash(entry):
    assert entry.RELEASES_DIR == "/opt/steamos-mounter/releases/"
    assert entry.OS_RELEASE == "/etc/os-release"


# --- release_root ----------------------------------------------------------


def test_release_root_resolves_the_opt_bin_and_current_links(tmp_path):
    opt = tmp_path / "opt" / "steamos-mounter"
    release = build_release(opt / "releases" / "0.1.0-20261009T000000Z")
    (release / "bin" / "steamos-mounter").write_bytes(ENTRY_POINT.read_bytes())
    (opt / "current").symlink_to(release.relative_to(opt), target_is_directory=True)
    (opt / "bin").symlink_to("current/bin", target_is_directory=True)

    module = load_entry_point(opt / "bin" / "steamos-mounter")

    assert module.release_root() == os.fspath(release)


def test_release_root_of_the_checkout_is_the_repository(entry):
    assert entry.release_root() == os.fspath(REPO)


# --- is_steamos ------------------------------------------------------------


@pytest.mark.parametrize(
    ("os_id", "expected"),
    [
        ("steamos", True),
        ('"steamos"', True),
        ("debian", False),
        ("arch", False),
        ("steamos-fork", False),
    ],
)
def test_is_steamos_reads_the_id_line(entry, monkeypatch, tmp_path, os_id, expected):
    os_release = write_os_release(tmp_path / "os-release", os_id)
    monkeypatch.setattr(entry, "OS_RELEASE", str(os_release))

    assert entry.is_steamos() is expected


def test_is_steamos_ignores_id_like(entry, monkeypatch, tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text("ID=arch\nID_LIKE=steamos\n", encoding="utf-8")
    monkeypatch.setattr(entry, "OS_RELEASE", str(os_release))

    assert entry.is_steamos() is False


def test_is_steamos_is_false_when_os_release_is_missing(entry, monkeypatch, tmp_path):
    monkeypatch.setattr(entry, "OS_RELEASE", str(tmp_path / "absent"))

    assert entry.is_steamos() is False


# --- tree_is_trusted -------------------------------------------------------


def test_tree_is_trusted_accepts_a_root_owned_release(entry, root_owner, tmp_path):
    release = build_release(tmp_path / "release")
    root_owner()

    assert entry.tree_is_trusted(os.fspath(release)) is True


def test_tree_is_trusted_rejects_the_real_non_root_owner(entry, tmp_path):
    release = build_release(tmp_path / "release")

    assert os.lstat(release).st_uid != 0
    assert entry.tree_is_trusted(os.fspath(release)) is False


@pytest.mark.parametrize(
    "foreign",
    ["", "lib/steamos_mounter", "lib/steamos_mounter/cli.py", "units"],
    ids=["release-root", "subdirectory", "nested-file", "units-dir"],
)
def test_tree_is_trusted_rejects_a_non_root_owner(entry, root_owner, tmp_path, foreign):
    release = build_release(tmp_path / "release")
    root_owner(release / foreign)

    assert entry.tree_is_trusted(os.fspath(release)) is False


@pytest.mark.parametrize(
    ("relative", "mode"),
    [
        ("", 0o775),
        ("lib/steamos_mounter", 0o775),
        ("lib/steamos_mounter", 0o757),
        ("lib/steamos_mounter/cli.py", 0o664),
        ("lib/steamos_mounter/cli.py", 0o646),
        ("bin/steamos-mounter", 0o777),
    ],
    ids=[
        "root-group",
        "subdir-group",
        "subdir-other",
        "file-group",
        "file-other",
        "script-world",
    ],
)
def test_tree_is_trusted_rejects_group_or_other_write(
    entry, root_owner, tmp_path, relative, mode
):
    release = build_release(tmp_path / "release")
    (release / relative).chmod(mode)
    root_owner()

    assert entry.tree_is_trusted(os.fspath(release)) is False


def test_tree_is_trusted_rejects_a_symlinked_subdirectory(entry, root_owner, tmp_path):
    # D003: the link itself sits in a root-owned 0755 directory and points at a
    # root-owned tree, so only an lstat of the subdirectory entry catches it.
    elsewhere = build_release(tmp_path / "elsewhere", files=["evil/cli.py"])
    release = build_release(tmp_path / "release")
    (release / "lib" / "steamos_mounter" / "platforms").symlink_to(
        elsewhere / "evil", target_is_directory=True
    )
    root_owner()

    assert entry.tree_is_trusted(os.fspath(release)) is False


def test_tree_is_trusted_rejects_a_symlinked_file(entry, root_owner, tmp_path):
    release = build_release(tmp_path / "release")
    (release / "lib" / "steamos_mounter" / "errors.py").symlink_to("cli.py")
    root_owner()

    assert entry.tree_is_trusted(os.fspath(release)) is False


@pytest.mark.parametrize(
    "victim",
    ["lib/steamos_mounter/cli.py", "units"],
    ids=["file", "directory"],
)
def test_tree_is_trusted_fails_closed_when_an_entry_vanishes_mid_walk(
    entry, root_owner, monkeypatch, tmp_path, victim
):
    # I009: the walk lists the entry, then it disappears before its lstat.
    release = build_release(tmp_path / "release")
    target = release / victim
    if target.is_dir():
        for child in target.iterdir():
            child.unlink()
    monkeypatch.setattr(os, "walk", walk_removing(target))
    root_owner()

    assert entry.tree_is_trusted(os.fspath(release)) is False
    assert not target.exists()


def test_tree_is_trusted_fails_closed_when_lstat_raises(
    entry, root_owner, monkeypatch, tmp_path
):
    # I009: any OSError from lstat (EACCES, EIO) fails closed, never raises.
    release = build_release(tmp_path / "release")
    root_owner()
    faking_lstat = os.lstat
    unreadable = os.fspath(release / "lib" / "steamos_mounter" / "cli.py")

    def lstat(path, *args, **kwargs):
        if os.fspath(path) == unreadable:
            raise PermissionError(13, "Permission denied", unreadable)
        return faking_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)

    assert entry.tree_is_trusted(os.fspath(release)) is False


def test_tree_is_trusted_fails_closed_on_an_unreadable_subdirectory(
    entry, root_owner, request, tmp_path
):
    # I009: os.walk would skip a directory it cannot scandir; the walk's
    # onerror re-raises, so the check fails closed instead of trusting it.
    release = build_release(tmp_path / "release")
    unreadable = release / "lib" / "steamos_mounter"
    unreadable.chmod(0o300)
    request.addfinalizer(lambda: unreadable.chmod(DIR_MODE))
    root_owner()

    assert os.geteuid() != 0  # root would read a 0300 directory anyway
    assert entry.tree_is_trusted(os.fspath(release)) is False


def test_tree_is_trusted_fails_closed_when_the_root_does_not_exist(
    entry, root_owner, tmp_path
):
    root_owner()

    assert entry.tree_is_trusted(os.fspath(tmp_path / "missing-release")) is False


def test_tree_is_trusted_fails_closed_when_a_subdirectory_vanishes_before_scandir(
    entry, root_owner, monkeypatch, tmp_path
):
    # I009: the subdirectory passes its own lstat, then disappears before the
    # walk descends into it.
    release = build_release(tmp_path / "release")
    victim = release / "lib" / "steamos_mounter" / "platforms"
    victim.mkdir(mode=DIR_MODE)
    root_owner()
    monkeypatch.setattr(os, "lstat", lstat_removing_dir(victim))

    assert entry.tree_is_trusted(os.fspath(release)) is False
    assert not victim.exists()


# --- main: root path -------------------------------------------------------


@pytest.mark.parametrize(
    "root",
    [
        "/home/deck/steamos-mounter",
        "/opt/steamos-mounter",
        "/opt/steamos-mounter/releases",
        "/opt/steamos-mounter/releases-old/0.1.0",
        "/opt/steamos-mounter-evil/releases/0.1.0",
    ],
)
def test_main_as_root_outside_releases_exits_1_before_importing_the_cli(
    entry, host, cli_calls, capsys, root
):
    host(euid=0, os_id="steamos", root=root)
    path_before = list(sys.path)

    assert entry.main() == 1

    captured = capsys.readouterr()
    assert captured.err == REFUSAL_LINE
    assert captured.out == ""
    assert cli_calls == []
    assert sys.path == path_before


def test_main_as_root_from_an_untrusted_release_exits_1(
    entry, host, cli_calls, capsys, releases_dir, root_owner
):
    release = build_release(releases_dir / "0.1.0")
    (release / "lib" / "steamos_mounter" / "cli.py").chmod(0o666)
    root_owner()
    host(euid=0, os_id="steamos", root=release)

    assert entry.main() == 1

    assert capsys.readouterr().err == REFUSAL_LINE
    assert cli_calls == []


def test_main_as_root_from_a_trusted_release_hands_over_to_the_cli(
    entry, host, cli_calls, releases_dir, root_owner
):
    release = build_release(releases_dir / "0.1.0")
    root_owner()
    host(euid=0, os_id="steamos", root=release)

    assert entry.main() == CLI_EXIT

    assert cli_calls == [(["list", "--json"], os.fspath(release))]
    assert sys.path[0] == os.fspath(release / "lib")


@pytest.mark.parametrize("os_id", ["debian", "arch"])
def test_main_as_root_on_another_os_exits_4_before_the_trust_check(
    entry, host, cli_calls, capsys, monkeypatch, releases_dir, os_id
):
    # D004 / DD-30: the platform guard runs before the location and trust checks.
    release = build_release(releases_dir / "0.1.0")
    trust_checks: list[str] = []
    monkeypatch.setattr(entry, "tree_is_trusted", trust_checks.append)
    host(euid=0, os_id=os_id, root=release)

    assert entry.main() == 4

    captured = capsys.readouterr()
    assert captured.err == PLATFORM_LINE
    assert captured.out == ""
    assert trust_checks == []
    assert cli_calls == []


def test_main_as_root_on_another_os_outside_releases_still_exits_4(
    entry, host, cli_calls, capsys
):
    host(euid=0, os_id="debian", root="/home/deck/steamos-mounter")

    assert entry.main() == 4

    assert capsys.readouterr().err == PLATFORM_LINE
    assert cli_calls == []


# --- main: non-root path ---------------------------------------------------


def test_main_as_user_inserts_lib_and_calls_the_cli(entry, host, cli_calls, tmp_path):
    release = build_release(tmp_path / "release")
    host(euid=DECK_UID, os_id="steamos", root=release)

    assert entry.main() == CLI_EXIT

    assert sys.path[0] == os.fspath(release / "lib")
    assert cli_calls == [(["list", "--json"], os.fspath(release))]


def test_main_as_user_falls_back_to_src_in_a_checkout(entry, host, cli_calls, tmp_path):
    checkout = build_release(
        tmp_path / "checkout",
        files=["bin/steamos-mounter", "src/steamos_mounter/__init__.py"],
    )
    host(euid=DECK_UID, os_id="steamos", root=checkout)

    assert entry.main() == CLI_EXIT

    assert sys.path[0] == os.fspath(checkout / "src")
    assert cli_calls == [(["list", "--json"], os.fspath(checkout))]


def test_main_as_user_leaves_the_platform_guard_to_the_cli(
    entry, host, cli_calls, capsys, tmp_path
):
    # The non-root path skips the entry guards; cli.main runs its own platform
    # guard first, so --help keeps working in a development checkout.
    checkout = build_release(tmp_path / "checkout", files=["src/x.py"])
    host(euid=DECK_UID, os_id="debian", root=checkout)

    assert entry.main() == CLI_EXIT

    assert cli_calls == [(["list", "--json"], os.fspath(checkout))]
    assert capsys.readouterr().err == ""
