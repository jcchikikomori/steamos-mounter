"""EVP-2 output comparison: tools/compare_mounts.py.

Design Doc: docs/design/steamos-mounter-design.md (section "Output Comparison"
and "Mount Options per Driver"). The script is a dev-only tool outside the
coverage source, so it is loaded by path. Its inputs are a ``findmnt -J``
capture and a two-line ``stat -c '%U %G %a'`` capture (mount root, then one
file written by ``deck``) for each side; the findmnt inputs are the synthetic
old/new pair, and the stat lines are built here. The expected-field table
itself lives in the script; these tests pin the verdict per field.
"""

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from tests.helpers.fixtures import load_fixture

REPO = Path(__file__).resolve().parents[2]
COMPARE_MOUNTS = REPO / "tools" / "compare_mounts.py"

OLD_FINDMNT = "compare-old-ntfs.json"
NEW_FINDMNT = "compare-new-fuseblk.json"
# ntfs-3g without uid/gid/umask: everything root-owned, 0777.
OLD_STAT = "root root 777\nroot root 777\n"
# ntfs-3g with uid=1000,gid=1000,umask=0022.
NEW_STAT = "deck deck 755\ndeck deck 644\n"

EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_USAGE = 2

FSTYPE = "fstype"
READ_WRITE = "read-write"
VFS_FLAGS = "vfs-options contains nosuid,nodev"
FILE_OWNER = "file owner"
FILE_MODE = "file mode"
DECK_CREATES = "deck can create a file"
TARGET = "target"
FIELD_ORDER = [
    FSTYPE,
    READ_WRITE,
    VFS_FLAGS,
    FILE_OWNER,
    FILE_MODE,
    DECK_CREATES,
    TARGET,
]


def load_compare_mounts() -> ModuleType:
    spec = importlib.util.spec_from_file_location("compare_mounts", COMPARE_MOUNTS)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def compare_mounts() -> ModuleType:
    return load_compare_mounts()


def findmnt(name: str) -> dict:
    return json.loads(load_fixture(name))


def set_field(capture: dict, key: str, value: str) -> dict:
    capture["filesystems"][0][key] = value
    return capture


def write_inputs(
    tmp_path: Path,
    *,
    old_findmnt: dict | None = None,
    new_findmnt: dict | None = None,
    old_stat: str = OLD_STAT,
    new_stat: str = NEW_STAT,
) -> list[str]:
    """The four argv paths: old findmnt, old stat, new findmnt, new stat."""
    contents = [
        json.dumps(old_findmnt or findmnt(OLD_FINDMNT)),
        old_stat,
        json.dumps(new_findmnt or findmnt(NEW_FINDMNT)),
        new_stat,
    ]
    names = ["old.json", "old.stat", "new.json", "new.stat"]
    for name, content in zip(names, contents, strict=True):
        (tmp_path / name).write_text(content, encoding="utf-8")
    return [str(tmp_path / name) for name in names]


def verdicts(output: str) -> dict[str, str]:
    """Field name -> status word, from the script's per-field lines."""
    result = {}
    for line in output.splitlines():
        status, _, rest = line.partition(" ")
        field, _, _ = rest.strip().partition(":")
        result[field] = status
    return result


def run(compare_mounts, capsys, argv: list[str]) -> tuple[int, str, str]:
    code = compare_mounts.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- the expected pair ------------------------------------------------------


def test_expected_pair_gives_only_equal_and_intended(compare_mounts, capsys, tmp_path):
    code, out, err = run(compare_mounts, capsys, write_inputs(tmp_path))

    assert code == EXIT_OK
    assert err == ""
    assert verdicts(out) == {
        FSTYPE: "equal",
        READ_WRITE: "equal",
        VFS_FLAGS: "intended",
        FILE_OWNER: "intended",
        FILE_MODE: "intended",
        DECK_CREATES: "equal",
        TARGET: "intended",
    }


def test_one_line_per_field_in_design_doc_order(compare_mounts, capsys, tmp_path):
    _, out, _ = run(compare_mounts, capsys, write_inputs(tmp_path))

    assert list(verdicts(out)) == FIELD_ORDER


def test_lines_show_the_observed_values(compare_mounts, capsys, tmp_path):
    _, out, _ = run(compare_mounts, capsys, write_inputs(tmp_path))

    lines = out.splitlines()
    assert lines[0] == "equal      fstype: old=fuseblk new=fuseblk"
    assert lines[2] == (
        "intended   vfs-options contains nosuid,nodev: old=none new=nosuid,nodev"
    )
    assert lines[3] == (
        "intended   file owner: old=root:root root:root new=deck:deck deck:deck"
    )
    assert lines[4] == "intended   file mode: old=777 777 new=755 644"
    assert lines[6] == (
        "intended   target: old=/run/smt-old new=/run/media/deck/SCRATCH"
    )


def test_same_registered_path_on_both_sides_is_equal(compare_mounts, capsys, tmp_path):
    old = set_field(findmnt(OLD_FINDMNT), "target", "/run/media/deck/SCRATCH")

    code, out, _ = run(compare_mounts, capsys, write_inputs(tmp_path, old_findmnt=old))

    assert code == EXIT_OK
    assert verdicts(out)[TARGET] == "equal"


# --- mutated new captures ---------------------------------------------------


def test_noexec_in_new_capture_is_unexpected(compare_mounts, capsys, tmp_path):
    new = set_field(
        findmnt(NEW_FINDMNT), "vfs-options", "rw,nosuid,nodev,noexec,relatime"
    )

    code, out, _ = run(compare_mounts, capsys, write_inputs(tmp_path, new_findmnt=new))

    assert code == EXIT_UNEXPECTED
    assert verdicts(out)[VFS_FLAGS] == "UNEXPECTED"
    assert "new=nosuid,nodev,noexec" in out


def test_root_owned_file_in_new_capture_is_unexpected(compare_mounts, capsys, tmp_path):
    new_stat = "deck deck 755\nroot root 644\n"

    code, out, _ = run(
        compare_mounts, capsys, write_inputs(tmp_path, new_stat=new_stat)
    )

    assert code == EXIT_UNEXPECTED
    assert verdicts(out)[FILE_OWNER] == "UNEXPECTED"
    assert verdicts(out)[FILE_MODE] == "intended"


def test_unexpected_line_names_the_expected_values(compare_mounts, capsys, tmp_path):
    new_stat = "deck deck 755\nroot root 644\n"

    _, out, _ = run(compare_mounts, capsys, write_inputs(tmp_path, new_stat=new_stat))

    assert out.splitlines()[3] == (
        "UNEXPECTED file owner: old=root:root root:root new=deck:deck root:root"
        " (expected old=root:root root:root new=deck:deck deck:deck)"
    )


@pytest.mark.parametrize(
    ("key", "value", "field"),
    [
        ("fstype", "ntfs3", FSTYPE),
        ("vfs-options", "ro,nosuid,nodev,relatime", READ_WRITE),
        ("fs-options", "ro,user_id=0,group_id=0,allow_other,blksize=4096", READ_WRITE),
        ("vfs-options", "rw,nodev,relatime", VFS_FLAGS),
        ("vfs-options", "rw,relatime", VFS_FLAGS),
        ("target", "/mnt/SCRATCH", TARGET),
        ("target", "/run/media/deck/STICK/SCRATCH", TARGET),
        ("target", "/run/media/deck", TARGET),
    ],
)
def test_wrong_new_mount_field_is_unexpected(
    compare_mounts, capsys, tmp_path, key, value, field
):
    new = set_field(findmnt(NEW_FINDMNT), key, value)

    code, out, _ = run(compare_mounts, capsys, write_inputs(tmp_path, new_findmnt=new))

    assert code == EXIT_UNEXPECTED
    assert verdicts(out)[field] == "UNEXPECTED"


def test_noatime_is_not_a_security_flag(compare_mounts, capsys, tmp_path):
    new = set_field(findmnt(NEW_FINDMNT), "vfs-options", "rw,nosuid,nodev,noatime")

    code, out, _ = run(compare_mounts, capsys, write_inputs(tmp_path, new_findmnt=new))

    assert code == EXIT_OK
    assert verdicts(out)[VFS_FLAGS] == "intended"


@pytest.mark.parametrize(
    ("new_stat", "field"),
    [
        ("deck deck 755\ndeck deck 777\n", FILE_MODE),
        ("deck deck 777\ndeck deck 644\n", FILE_MODE),
        ("deck root 755\ndeck deck 644\n", FILE_OWNER),
    ],
)
def test_wrong_new_stat_is_unexpected(
    compare_mounts, capsys, tmp_path, new_stat, field
):
    code, out, _ = run(
        compare_mounts, capsys, write_inputs(tmp_path, new_stat=new_stat)
    )

    assert code == EXIT_UNEXPECTED
    assert verdicts(out)[field] == "UNEXPECTED"


def test_root_owned_new_mount_root_means_deck_cannot_create(
    compare_mounts, capsys, tmp_path
):
    new_stat = "root root 755\ndeck deck 644\n"

    code, out, _ = run(
        compare_mounts, capsys, write_inputs(tmp_path, new_stat=new_stat)
    )

    assert code == EXIT_UNEXPECTED
    assert verdicts(out)[DECK_CREATES] == "UNEXPECTED"
    assert "deck can create a file: old=yes new=no" in out


def test_old_capture_with_nosuid_is_unexpected(compare_mounts, capsys, tmp_path):
    old = set_field(findmnt(OLD_FINDMNT), "vfs-options", "rw,nosuid,relatime")

    code, out, _ = run(compare_mounts, capsys, write_inputs(tmp_path, old_findmnt=old))

    assert code == EXIT_UNEXPECTED
    assert verdicts(out)[VFS_FLAGS] == "UNEXPECTED"


# --- bad input --------------------------------------------------------------


def test_wrong_argument_count_is_usage_error(compare_mounts, capsys):
    code, out, err = run(compare_mounts, capsys, ["only-one"])

    assert code == EXIT_USAGE
    assert out == ""
    assert err.startswith("usage: compare_mounts.py OLD_FINDMNT OLD_STAT")


def test_missing_input_file_is_usage_error(compare_mounts, capsys, tmp_path):
    argv = write_inputs(tmp_path)
    argv[2] = str(tmp_path / "absent.json")

    code, out, err = run(compare_mounts, capsys, argv)

    assert code == EXIT_USAGE
    assert out == ""
    assert "absent.json" in err


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"filesystems": []}',
        '{"filesystems": [{"target": "/x"}, {"target": "/y"}]}',
        '{"filesystems": [{"target": "/x"}]}',
        '{"filesystems": ["/x"]}',
        '{"filesystems": [{"target": "/x", "source": "/dev/loop0", "fstype": 3,'
        ' "vfs-options": "rw", "fs-options": "rw"}]}',
    ],
)
def test_bad_findmnt_capture_is_usage_error(compare_mounts, capsys, tmp_path, content):
    argv = write_inputs(tmp_path)
    Path(argv[2]).write_text(content, encoding="utf-8")

    code, out, err = run(compare_mounts, capsys, argv)

    assert code == EXIT_USAGE
    assert out == ""
    assert "new.json" in err


@pytest.mark.parametrize(
    "content",
    [
        "",
        "deck deck 755\n",
        "deck deck 755\ndeck deck 644\ndeck deck 644\n",
        "deck deck\ndeck deck 644\n",
        "deck deck 755\ndeck deck rw-\n",
        "deck deck 755\ndeck deck 89\n",
    ],
)
def test_bad_stat_capture_is_usage_error(compare_mounts, capsys, tmp_path, content):
    argv = write_inputs(tmp_path)
    Path(argv[3]).write_text(content, encoding="utf-8")

    code, out, err = run(compare_mounts, capsys, argv)

    assert code == EXIT_USAGE
    assert out == ""
    assert "new.stat" in err
