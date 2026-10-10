"""Setup shared by the installer tests: a host skeleton and a staged release.

Design Doc "Python install", "Python uninstall" and "Mock Boundary
Decisions": every file effect is real under ``HostPaths(root=tmp_path)`` with
the test uid as the trusted owner; systemctl, udevadm, setfacl and lsblk go
through the ``FakeRunner``. ``stage_release`` lays a release out the way
``install.sh`` does: ``bin/``, ``data/``, ``README.md`` and the package as
``lib/steamos_mounter``, dirs 0755, files 0644, the entry point 0755, no
``__pycache__`` and no symlinks. ``package=False`` stages a one-file package
instead of the real one, so the unit tests compile in a blink.

The running release (``ctx.release_root``, work plan decision item 2) is set
with ``release_ctx``: the Context field the installer compares ``--release``
against.
"""

import contextlib
import dataclasses
import hashlib
import os
import shutil
import stat
from collections.abc import Iterator
from pathlib import Path

from steamos_mounter import __version__
from steamos_mounter.context import Context
from steamos_mounter.platforms.steamos import TOOLS
from tests.helpers.cli_env import steamos_host
from tests.helpers.fake_runner import Answer, FakeRunner
from tests.helpers.flows import SETFACL, SYSTEMCTL

REPO = Path(__file__).resolve().parents[2]
RELEASE_NAME = "0.1.0-20261008T000000Z"
OPT = "opt/steamos-mounter"
RELEASES = f"{OPT}/releases"
CURRENT = f"{OPT}/current"
BIN_LINK = f"{OPT}/bin"
REGISTRY = "etc/steamos-mounter/config.toml"
KEPT_REGISTRY = "var/lib/steamos-mounter/kept-config.toml"
KEYS_DIR = "var/lib/steamos-mounter/keys"
RUN_TREE = "run/steamos-mounter"
ETC_FILES = (
    "etc/atomic-update.conf.d/steamos-mounter.conf",
    "etc/systemd/system/steamos-mounter@.service",
    "etc/systemd/system/steamos-mounter-auto@.service",
    "etc/systemd/system/steamos-mounter-key@.service",
    "etc/udev/rules.d/90-steamos-mounter.rules",
)
# The parts of the host the installer expects to exist already.
SYSTEM_DIRS = (
    "etc/systemd/system",
    "etc/udev/rules.d",
    "etc/atomic-update.conf.d",
    "var/lib",
    "opt",
    "run",
)
DIR_MODE = 0o755
FILE_MODE = 0o644
ENTRY_POINT = "bin/steamos-mounter"
UDEVADM_RELOAD = (TOOLS.udevadm, "control", "--reload")
DAEMON_RELOAD = (SYSTEMCTL, "daemon-reload")
LIST_UNITS = (
    SYSTEMCTL,
    "list-units",
    "--all",
    "--plain",
    "--no-legend",
    "--no-pager",
    "--full",
    "--",
)
KEY_UNITS = (*LIST_UNITS, "steamos-mounter-key@*")
INSTANCES = (*LIST_UNITS, "steamos-mounter@*", "steamos-mounter-auto@*")


def system_tree(root: Path) -> None:
    """A SteamOS host before the first install: os-release and the system dirs."""
    steamos_host(root)
    for relative in SYSTEM_DIRS:
        (root / relative).mkdir(parents=True, exist_ok=True)


def stage_release(
    root: Path, name: str = RELEASE_NAME, *, package: bool = True
) -> Path:
    """Copy the repository into ``releases/<name>`` with the install.sh modes."""
    releases = root / RELEASES
    releases.mkdir(parents=True, exist_ok=True)
    for directory in (root / OPT, releases):
        directory.chmod(DIR_MODE)
    release = releases / name
    release.mkdir()
    shutil.copytree(REPO / "bin", release / "bin")
    shutil.copytree(REPO / "data", release / "data")
    shutil.copy2(REPO / "README.md", release / "README.md")
    lib = release / "lib" / "steamos_mounter"
    if package:
        ignore = shutil.ignore_patterns("__pycache__")
        shutil.copytree(REPO / "src" / "steamos_mounter", lib, ignore=ignore)
    else:
        lib.mkdir(parents=True)
        (lib / "__init__.py").write_text(f'__version__ = "{__version__}"\n')
    set_release_modes(release)
    return release


def set_release_modes(release: Path) -> None:
    for path in [release, *release.rglob("*")]:
        path.chmod(DIR_MODE if path.is_dir() else FILE_MODE)
    (release / ENTRY_POINT).chmod(DIR_MODE)


def release_ctx(ctx: Context, release: Path | None) -> Context:
    """``ctx`` as the entry point of ``release`` builds it (None: unknown)."""
    root = None if release is None else str(release)
    return dataclasses.replace(ctx, release_root=root)


def script_reloads(runner: FakeRunner) -> None:
    """daemon-reload, udevadm reload and setfacl all succeed, every time."""
    runner.on(DAEMON_RELOAD, Answer(), repeat=True)
    runner.on(UDEVADM_RELOAD, Answer(), repeat=True)
    runner.on(SETFACL, Answer(), repeat=True)


def units_answer(*units: str) -> Answer:
    """``systemctl list-units --plain --no-legend`` lines for ``units``."""
    lines = "".join(f"{unit} loaded inactive dead steamos-mounter\n" for unit in units)
    return Answer(stdout=lines.encode())


Snapshot = dict[str, tuple[object, ...]]


def snapshot(root: Path) -> Snapshot:
    """Every path under ``root`` but ``__pycache__``, as the filesystem sees it.

    Type, mode, owner and inode for every entry; for files and symlinks also
    ``st_mtime_ns`` and the content (sha256) or link target. A path rewritten
    with the same bytes gets a new inode (atomic rename) or a new mtime, so an
    equal snapshot proves nothing was written. Directory mtimes are left out:
    a lock file opened in a directory is not a write to the tree.
    """
    found: Snapshot = {}
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts:
            continue
        info = os.lstat(path)
        common = (stat.S_IMODE(info.st_mode), info.st_uid, info.st_ino)
        if stat.S_ISLNK(info.st_mode):
            entry = ("link", *common, info.st_mtime_ns, os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            entry = ("dir", *common)
        else:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entry = ("file", *common, info.st_mtime_ns, digest)
        found[str(path.relative_to(root))] = entry
    return found


def paths_under(root: Path) -> set[str]:
    """Every path under ``root``, relative to ``root.parent`` (``etc/...``)."""
    return {str(path.relative_to(root.parent)) for path in root.rglob("*")}


@contextlib.contextmanager
def pinned_umask(mask: int = 0o022) -> Iterator[None]:
    """The test process's umask fixed to ``mask``, restored afterwards."""
    previous = os.umask(mask)
    try:
        yield
    finally:
        os.umask(previous)


def mode_of(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)
