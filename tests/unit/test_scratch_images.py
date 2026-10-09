"""Stage A scratch images: tools/make_scratch_images.sh and tools/ntfs_set_dirty.py.

Design Doc: docs/design/steamos-mounter-design.md (sections "On-device
Verification Procedure" Stage A, "Fixtures", I003; NFR-15, NFR-16).

The images are built for real with the ntfs-3g tools of the Docker image
(mkntfs, ntfscp) and checked with ntfs-3g.probe and ntfsinfo, hence
@pytest.mark.ntfstools. Everything is written under tmp_path; the refusal
tests prove that a path under /dev (directly or through a symlink) and a
block device are never written.

Probe exit codes (libntfs-3g ``ntfs_volume_error``): 0 OK, 14 hibernated,
15 unclean unmount. The Design Doc's Docker checks are 0 for clean.img, 14 for
unsafe.img and the dirty flag read back for dirty.img. VOLUME_IS_DIRTY alone
does not make ntfs-3g.probe refuse (measured: exit 0 with ntfs-3g 2022.10.3 in
the dev image; 15 needs an unclean $LogFile), so dirty.img is pinned at 0 here.
It exists for the kernel ntfs3 driver, which refuses a dirty volume rw; the
Deck's own probe result for dirty.img is checked on the Deck (task 52).
"""

import importlib.util
import stat
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.ntfstools

REPO = Path(__file__).resolve().parents[2]
MAKE_IMAGES = REPO / "tools" / "make_scratch_images.sh"
SET_DIRTY = REPO / "tools" / "ntfs_set_dirty.py"

SH = "/bin/sh"
PYTHON = sys.executable
PROBE = "/usr/bin/ntfs-3g.probe"
NTFSINFO = "/usr/bin/ntfsinfo"

IMAGE_NAMES = ("clean.img", "dirty.img", "unsafe.img")
IMAGE_SIZE = 64 * 1024 * 1024
EXIT_REFUSED = 2
EXIT_NOT_NTFS = 1
PROBE_OK = 0
PROBE_HIBERNATED = 14
# A writable tmpfs under /dev in the container: what a missing guard would hit.
DEV_SHM = Path("/dev/shm")
# Never present in the container; stands for "a disk".
BLOCK_DEVICE_PATH = "/dev/sdz9"


def run(*argv: str | Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(arg) for arg in argv],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def volume_flags(image: Path) -> str:
    """The ``Volume Flags`` value ntfsinfo reads from ``$Volume``."""
    result = run(NTFSINFO, "--force", "-m", image)
    assert result.returncode == 0, result.stderr
    for line in result.stdout.splitlines():
        label, _, value = line.strip().partition(":")
        if label == "Volume Flags":
            return value.strip()
    raise AssertionError(f"no Volume Flags line in ntfsinfo output:\n{result.stdout}")


def load_set_dirty() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ntfs_set_dirty", SET_DIRTY)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def images(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The three images, built once for the module."""
    out = tmp_path_factory.mktemp("scratch")
    result = run(SH, MAKE_IMAGES, out)
    assert result.returncode == 0, result.stderr
    return out


@pytest.fixture
def dev_shm_dir() -> Iterator[Path]:
    """A fresh directory under /dev/shm, removed afterwards."""
    path = DEV_SHM / f"steamos-mounter-test-{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        for child in path.iterdir():
            child.unlink()
        path.rmdir()


# --- make_scratch_images.sh: the images -------------------------------------


def test_make_images_writes_exactly_three_64_mib_regular_files(images):
    entries = sorted(images.iterdir())

    assert [entry.name for entry in entries] == sorted(IMAGE_NAMES)
    for entry in entries:
        assert stat.S_ISREG(entry.lstat().st_mode), entry
        assert entry.stat().st_size == IMAGE_SIZE, entry


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("clean.img", PROBE_OK),
        ("dirty.img", PROBE_OK),
        ("unsafe.img", PROBE_HIBERNATED),
    ],
)
def test_probe_readwrite_exit_code_per_image(images, name, expected):
    result = run(PROBE, "--readwrite", images / name)

    assert result.returncode == expected, result.stderr


def test_dirty_image_reads_back_volume_is_dirty(images):
    assert volume_flags(images / "dirty.img") == "0x0001 DIRTY"


@pytest.mark.parametrize("name", ["clean.img", "unsafe.img"])
def test_other_images_are_not_flagged_dirty(images, name):
    assert volume_flags(images / name) == "0x0000"


def test_each_image_is_a_separate_volume_with_its_own_serial(images):
    # Boot sector bytes 0x48..0x4F: the volume serial behind /dev/disk/by-uuid.
    serials = {(images / name).read_bytes()[0x48:0x50] for name in IMAGE_NAMES}

    assert len(serials) == len(IMAGE_NAMES)


# --- make_scratch_images.sh: refusals (NFR-15) -------------------------------


def test_make_images_without_argument_exits_2():
    result = run(SH, MAKE_IMAGES)

    assert result.returncode == EXIT_REFUSED
    assert "usage" in result.stderr


def test_make_images_refuses_a_block_device_path_under_dev():
    result = run(SH, MAKE_IMAGES, BLOCK_DEVICE_PATH)

    assert result.returncode == EXIT_REFUSED
    assert "refused" in result.stderr
    assert not Path(BLOCK_DEVICE_PATH).exists()


def test_make_images_refuses_an_existing_directory_under_dev(dev_shm_dir):
    result = run(SH, MAKE_IMAGES, dev_shm_dir)

    assert result.returncode == EXIT_REFUSED
    assert "refused" in result.stderr
    assert list(dev_shm_dir.iterdir()) == []


def test_make_images_refuses_a_symlink_that_resolves_under_dev(tmp_path, dev_shm_dir):
    link = tmp_path / "out"
    link.symlink_to(dev_shm_dir)

    result = run(SH, MAKE_IMAGES, link)

    assert result.returncode == EXIT_REFUSED
    assert "refused" in result.stderr
    assert list(dev_shm_dir.iterdir()) == []


def test_make_images_refuses_a_missing_output_directory(tmp_path):
    missing = tmp_path / "missing"

    result = run(SH, MAKE_IMAGES, missing)

    assert result.returncode == EXIT_REFUSED
    assert "refused" in result.stderr
    assert not missing.exists()


def test_make_images_refuses_a_regular_file_as_output_directory(tmp_path):
    target = tmp_path / "file"
    target.write_bytes(b"keep")

    result = run(SH, MAKE_IMAGES, target)

    assert result.returncode == EXIT_REFUSED
    assert "refused" in result.stderr
    assert target.read_bytes() == b"keep"


def test_make_images_never_overwrites_an_existing_image(tmp_path):
    existing = tmp_path / "unsafe.img"
    existing.write_bytes(b"keep")

    result = run(SH, MAKE_IMAGES, tmp_path)

    assert result.returncode == EXIT_REFUSED
    assert "exists" in result.stderr
    assert existing.read_bytes() == b"keep"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["unsafe.img"]


def test_make_images_never_follows_an_image_symlink(tmp_path, dev_shm_dir):
    victim = dev_shm_dir / "disk"
    victim.write_bytes(b"keep")
    (tmp_path / "clean.img").symlink_to(victim)

    result = run(SH, MAKE_IMAGES, tmp_path)

    assert result.returncode == EXIT_REFUSED
    assert "exists" in result.stderr
    assert victim.read_bytes() == b"keep"


# --- ntfs_set_dirty.py -------------------------------------------------------


def test_set_dirty_without_argument_exits_2():
    result = run(PYTHON, SET_DIRTY)

    assert result.returncode == EXIT_REFUSED
    assert "usage" in result.stderr


def test_set_dirty_refuses_a_block_device_path_under_dev():
    result = run(PYTHON, SET_DIRTY, BLOCK_DEVICE_PATH)

    assert result.returncode == EXIT_REFUSED
    assert "refused" in result.stderr
    assert not Path(BLOCK_DEVICE_PATH).exists()


def test_set_dirty_refuses_a_regular_file_under_dev(dev_shm_dir):
    target = dev_shm_dir / "disk.img"
    target.write_bytes(b"keep")

    result = run(PYTHON, SET_DIRTY, target)

    assert result.returncode == EXIT_REFUSED
    assert "refused" in result.stderr
    assert target.read_bytes() == b"keep"


def test_set_dirty_refuses_a_symlink_that_resolves_under_dev(tmp_path, dev_shm_dir):
    target = dev_shm_dir / "disk.img"
    target.write_bytes(b"keep")
    link = tmp_path / "disk.img"
    link.symlink_to(target)

    result = run(PYTHON, SET_DIRTY, link)

    assert result.returncode == EXIT_REFUSED
    assert "under /dev" in result.stderr
    assert target.read_bytes() == b"keep"


def test_set_dirty_refuses_a_missing_file(tmp_path):
    missing = tmp_path / "missing.img"

    result = run(PYTHON, SET_DIRTY, missing)

    assert result.returncode == EXIT_REFUSED
    assert "refused" in result.stderr
    assert not missing.exists()


def test_set_dirty_refuses_a_directory(tmp_path):
    result = run(PYTHON, SET_DIRTY, tmp_path)

    assert result.returncode == EXIT_REFUSED
    assert "not a regular file" in result.stderr


@pytest.mark.parametrize(
    "content",
    [b"", b"\0" * 65536, b"\xeb\x52\x90EXFAT   " + b"\0" * 65524],
    ids=["empty", "zeros", "exfat-boot"],
)
def test_set_dirty_rejects_a_file_that_is_not_ntfs(tmp_path, content):
    target = tmp_path / "other.img"
    target.write_bytes(content)

    result = run(PYTHON, SET_DIRTY, target)

    assert result.returncode == EXIT_NOT_NTFS
    assert "not NTFS" in result.stderr
    assert target.read_bytes() == content


def test_set_dirty_is_idempotent_on_a_dirty_image(images, tmp_path):
    target = tmp_path / "again.img"
    target.write_bytes((images / "dirty.img").read_bytes())

    result = run(PYTHON, SET_DIRTY, target)

    assert result.returncode == 0, result.stderr
    assert volume_flags(target) == "0x0001 DIRTY"
    # $MFTMirr still matches $MFT, otherwise the probe reports corruption (13).
    assert run(PROBE, "--readwrite", target).returncode == PROBE_OK


@pytest.mark.parametrize(
    ("mode", "reason"),
    [
        (stat.S_IFBLK | 0o660, "block device"),
        (stat.S_IFCHR | 0o666, "not a regular file"),
        (stat.S_IFDIR | 0o755, "not a regular file"),
    ],
    ids=["block", "char", "dir"],
)
def test_refusal_reason_names_non_regular_files(mode, reason):
    module = load_set_dirty()
    target = Path("/tmp/x.img")

    assert reason in module.refusal_reason(target, target, mode)


@pytest.mark.parametrize(
    ("given", "resolved"),
    [
        ("/dev/sdb5", "/dev/sdb5"),
        ("/dev", "/dev"),
        ("/tmp/link.img", "/dev/loop0"),
        ("/dev/disk/by-uuid/X", "/tmp/x.img"),
    ],
    ids=["under-dev", "dev-itself", "resolves-under-dev", "given-under-dev"],
)
def test_refusal_reason_names_dev_paths(given, resolved):
    module = load_set_dirty()

    reason = module.refusal_reason(Path(given), Path(resolved), stat.S_IFREG | 0o644)

    assert "under /dev" in reason


def test_refusal_reason_accepts_a_regular_file_outside_dev():
    module = load_set_dirty()
    target = Path("/tmp/devices/x.img")

    assert module.refusal_reason(target, target, stat.S_IFREG | 0o644) is None


def test_set_dirty_accepts_a_path_relative_to_the_working_directory(images, tmp_path):
    target = tmp_path / "copy.img"
    target.write_bytes((images / "clean.img").read_bytes())

    result = subprocess.run(
        [PYTHON, str(SET_DIRTY), target.name],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    assert volume_flags(target) == "0x0001 DIRTY"
