"""``add`` and ``remove``: registration, its refusals, the key path, unwiring.

Design Doc "CLI Contract > Commands" (``add`` steps 1 to 7, ``remove``),
"Key Store", "Fixed-path Rules" (DD-31 rule 8, DD-34 rule 9), "Required
Specific Tests" (Absent registry file I001, Base child, Add on a fresh
``/run``, Auto name vs registered path), DD-02, DD-16, DD-28; PRD AC-001,
AC-002, AC-049, AC-050, AC-055 and the Won't list (LUKS, xfs). ADR-0002 D6
and ADR-0004 D4, D8.

Real registry, wiring links, key files and records under ``tmp_path``;
lsblk, findmnt, setfacl, cryptsetup and systemctl through the fake runner.
"""

import io
import logging
import os
import stat
import sys
from pathlib import Path

import pytest

from steamos_mounter import config, wiring
from steamos_mounter.errors import ExitCode
from tests.helpers.builders import (
    MEDIABOX,
    PERSONAL,
    RegistryVolume,
    record_dict,
    registry_text,
)
from tests.helpers.cli_env import (
    BROKEN_REGISTRY,
    CLI,
    DAEMON_RELOAD,
    DETAILS,
    MEDIABOX_LINK,
    MEDIABOX_PATH,
    MEDIABOX_RECORD,
    MEDIABOX_REGISTRY,
    MEDIABOX_UNIT,
    MEDIABOX_UUID,
    PERSONAL_KEY,
    PERSONAL_KEY_UNIT,
    PERSONAL_PATH,
    PERSONAL_RECORD,
    PERSONAL_REGISTRY,
    PERSONAL_UNIT,
    PERSONAL_UUID,
    REGISTRY_FILE,
    SYSTEMD_SYSTEM,
    files_under,
    findmnt_rows,
    given_host,
    partition,
    run_cli,
    script_setfacl,
    script_table,
    script_tree,
    script_unit,
    show_argv,
    systemctl_calls,
    tree_with,
    verb_argv,
)
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import (
    CRYPTSETUP,
    SETFACL,
    make_keys_dir,
    write_key_file,
    write_record,
)

TEMPLATE = "/etc/systemd/system/steamos-mounter@.service"
TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"
TEST_ARGV = (CRYPTSETUP, "open", "--test-passphrase", "--type", "bitlk", "--key-file=-")
MEDIABOX_ADDED = (
    f"registered MEDIABOX ({MEDIABOX_UUID}) at {MEDIABOX_PATH}\n"
    f"mounting MEDIABOX at {MEDIABOX_PATH} now\n"
)


def registry_file(root: Path) -> Path:
    return root / REGISTRY_FILE


def registry_bytes(root: Path) -> bytes | None:
    path = registry_file(root)
    return path.read_bytes() if path.exists() else None


def script_start(fake_runner, unit: str = MEDIABOX_UNIT, *, state: str = "inactive"):
    fake_runner.on(DAEMON_RELOAD, Answer(), repeat=True)
    script_unit(fake_runner, unit, state)
    fake_runner.on(verb_argv("start", unit, block=False), Answer())


@pytest.fixture
def host(ctx, tmp_path, fake_runner):
    """A SteamOS host after install, the Deck's devices plugged in, no registry file."""
    given_host(ctx, tmp_path)
    script_tree(fake_runner)
    script_table(fake_runner)
    return tmp_path


def stdin_key(monkeypatch, value: bytes = TEST_KEY) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(value + b"\n")))


# --- add: the registration (AC-001, I001) ---------------------------------------------


def test_add_registers_one_entry(ctx, host, fake_runner):
    script_start(fake_runner)

    result = run_cli(ctx, "add", "--device", "/dev/sdb5")

    assert (result.code, result.out, result.err) == (ExitCode.OK, MEDIABOX_ADDED, "")
    assert registry_file(host).read_text(encoding="utf-8") == registry_text((MEDIABOX,))
    assert os.readlink(host / MEDIABOX_LINK) == TEMPLATE
    assert systemctl_calls(fake_runner) == [
        DAEMON_RELOAD,
        show_argv(MEDIABOX_UNIT),
        verb_argv("start", MEDIABOX_UNIT, block=False),
    ]


def test_the_registry_and_wiring_are_written_before_daemon_reload(
    ctx, host, fake_runner
):
    seen = []

    def check(_command) -> None:
        seen.append((registry_file(host).exists(), (host / MEDIABOX_LINK).is_symlink()))

    fake_runner.on(DAEMON_RELOAD, Answer(), hook=check)
    script_unit(fake_runner, MEDIABOX_UNIT, "inactive")
    fake_runner.on(verb_argv("start", MEDIABOX_UNIT, block=False), Answer())

    assert run_cli(ctx, "add", "--device", "/dev/sdb5").code == ExitCode.OK
    assert seen == [(True, True)]


def test_first_add_creates_registry(ctx, host, fake_runner):
    script_start(fake_runner)
    assert not registry_file(host).exists()

    assert run_cli(ctx, "add", "--uuid", MEDIABOX_UUID).code == ExitCode.OK

    mode = os.lstat(registry_file(host)).st_mode
    assert stat.S_IMODE(mode) == 0o644
    assert config.load(ctx).volumes[0].name == "MEDIABOX"
    assert len(config.load(ctx).volumes) == 1


def test_add_with_name_path_drivers_and_flags(ctx, host, fake_runner, host_tree):
    host_tree.link_by_uuid(MEDIABOX_UUID, "sdb5")
    unit = MEDIABOX_UNIT
    script_start(fake_runner, unit)

    result = run_cli(
        ctx,
        "add",
        "--device",
        "/dev/disk/by-uuid/01D95F1575592A30",
        "--name",
        "Media.Box_1",
        "--path",
        "/run/media/deck/Movies",
        "--drivers",
        "ntfs-3g, ntfs3:ro",
        "--allow-suid",
        "--allow-devices",
    )

    assert result.code == ExitCode.OK, result.err
    expected = RegistryVolume(
        name="Media.Box_1",
        uuid=MEDIABOX_UUID,
        path="/run/media/deck/Movies",
        fstype="ntfs",
        drivers=("ntfs-3g", "ntfs3:ro"),
        nosuid=False,
        nodev=False,
    )
    assert registry_file(host).read_text(encoding="utf-8") == registry_text((expected,))


def test_add_does_not_start_an_instance_that_already_runs(ctx, host, fake_runner):
    script_start(fake_runner, state="active")

    result = run_cli(ctx, "add", "--device", "/dev/sdb5")

    assert result.out == f"registered MEDIABOX ({MEDIABOX_UUID}) at {MEDIABOX_PATH}\n"
    assert verb_argv("start", MEDIABOX_UNIT, block=False) not in fake_runner.argvs


def test_a_start_that_fails_still_registers_and_says_what_to_run(
    ctx, host, fake_runner
):
    fake_runner.on(DAEMON_RELOAD, Answer())
    script_unit(fake_runner, MEDIABOX_UNIT, "failed")
    fake_runner.on(
        verb_argv("start", MEDIABOX_UNIT, block=False),
        Answer(returncode=1, stderr=b"Job failed"),
    )

    result = run_cli(ctx, "add", "--device", "/dev/sdb5")

    assert result.code == ExitCode.OK
    assert result.out.splitlines()[-1] == (
        f"MEDIABOX could not be mounted now. Run {CLI} mount --volume MEDIABOX"
    )


def test_an_auto_mounted_volume_learns_its_fixed_path_applies_later(
    ctx, tmp_path, fake_runner
):
    given_host(ctx, tmp_path)
    script_tree(fake_runner)
    script_table(
        fake_runner,
        findmnt_rows(("/run/media/deck/MEDIABOX-2", "/dev/sdb5", "fuseblk", "8:21")),
    )
    script_start(fake_runner)

    result = run_cli(ctx, "add", "--device", "/dev/sdb5")

    assert result.code == ExitCode.OK
    assert result.out.splitlines()[-1] == (
        "MEDIABOX is mounted at /run/media/deck/MEDIABOX-2 now. The fixed path"
        " applies from the next plug-in, boot, or mount after an unmount"
    )


# --- add: refusals (AC-002, DD-02, D013 reasons) -------------------------------------


@pytest.mark.parametrize(
    ("device", "reason"),
    [
        ("/dev/sda1", "ext4 (SteamOS handles it)"),
        ("/dev/nvme0n1p8", "OS partition"),
        ("/dev/nvme0n1p4", "OS partition"),
        ("/dev/dm-0", "unlocked mapping: register its container /dev/sdb1"),
        ("/dev/sdb2", "no filesystem"),
        ("/dev/zram0", "unsupported type swap"),
    ],
    ids=["ext4", "os-home", "os-rootfs", "crypt", "no-fs", "swap"],
)
def test_add_refuses_ineligible_devices(ctx, host, fake_runner, device, reason):
    result = run_cli(ctx, "add", "--device", device)

    assert result.code == ExitCode.REFUSED
    kname = device.rpartition("/")[2]
    assert result.err == (
        f"steamos-mounter: cannot register /dev/{kname}: {reason}. {DETAILS}\n"
    )
    assert not registry_file(host).exists()
    assert systemctl_calls(fake_runner) == []


def test_add_refuses_ext4(ctx, host, fake_runner):
    result = run_cli(ctx, "add", "--device", "/dev/sda1")

    assert result.code == ExitCode.REFUSED
    assert "ext4 (SteamOS handles it)" in result.err
    assert not registry_file(host).exists()


def test_add_refuses_os_partition(ctx, host, fake_runner):
    result = run_cli(ctx, "add", "--uuid", "095a2a0e-2f44-49b9-8b43-d16fdc7f21c2")

    assert result.code == ExitCode.REFUSED
    assert "cannot register /dev/nvme0n1p8: OS partition." in result.err


def test_add_refuses_unknown_os_set(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path, os_set=False)
    script_tree(fake_runner)

    result = run_cli(ctx, "add", "--device", "/dev/sdb5")

    assert result.code == ExitCode.REFUSED
    assert "OS partition list unreadable" in result.err
    assert not registry_file(tmp_path).exists()
    assert systemctl_calls(fake_runner) == []


@pytest.mark.parametrize("fstype", ["crypto_LUKS", "xfs", "ext4"])
def test_add_refuses_the_prd_wont_list(ctx, tmp_path, fake_runner, fstype):
    given_host(ctx, tmp_path)
    script_tree(
        fake_runner,
        tree_with(partition("sdc1", fstype=fstype, uuid="1234-ABCD", label="X")),
    )

    result = run_cli(ctx, "add", "--device", "/dev/sdc1")

    assert result.code == ExitCode.REFUSED
    expected = "ext4 (SteamOS handles it)" if fstype == "ext4" else fstype
    assert expected in result.err


def test_add_refuses_a_registered_uuid(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path, registry=MEDIABOX_REGISTRY)
    script_tree(fake_runner)
    before = registry_bytes(tmp_path)

    result = run_cli(ctx, "add", "--device", "/dev/sdb5", "--name", "OTHER")

    assert result.code == ExitCode.REFUSED
    assert "already registered as MEDIABOX" in result.err
    assert registry_bytes(tmp_path) == before


def test_add_refuses_a_uuid_held_by_an_invalid_entry(ctx, tmp_path, fake_runner):
    invalid = MEDIABOX_REGISTRY.replace(MEDIABOX_PATH, "/mnt/MEDIABOX")
    given_host(ctx, tmp_path, registry=invalid)
    script_tree(fake_runner)

    result = run_cli(ctx, "add", "--device", "/dev/sdb5")

    assert result.code == ExitCode.REFUSED
    assert "already registered by an invalid registry entry" in result.err


@pytest.mark.parametrize("by", ["device", "uuid"])
def test_add_refuses_a_uuid_two_devices_share(ctx, tmp_path, fake_runner, by):
    given_host(ctx, tmp_path)
    script_tree(
        fake_runner,
        tree_with(
            partition("sdc1", fstype="exfat", uuid="1234-ABCD", label="A"),
            partition("sdd1", fstype="exfat", uuid="1234-abcd", label="B"),
        ),
    )
    argv = ("--device", "/dev/sdc1") if by == "device" else ("--uuid", "1234-ABCD")

    result = run_cli(ctx, "add", *argv)

    assert result.code == ExitCode.REFUSED
    assert result.err == (
        f"steamos-mounter: two devices share this UUID; unplug one. {DETAILS}\n"
    )


def test_add_internal_non_os(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path)
    internal = partition(
        "nvme0n1p9",
        fstype="ntfs",
        uuid="2A5C3B1C5C3AE3A1",
        label="WINDATA",
        partuuid="11111111-2222-3333-4444-555555555555",
        hotplug=False,
    )
    script_tree(fake_runner, tree_with(internal))
    script_table(fake_runner)
    script_start(
        fake_runner, "steamos-mounter@dev-disk-by\\x2duuid-2A5C3B1C5C3AE3A1.service"
    )

    result = run_cli(ctx, "add", "--device", "/dev/nvme0n1p9")

    assert result.code == ExitCode.OK, result.err
    assert config.load(ctx).volumes[0].path == "/run/media/deck/WINDATA"


def test_add_whole_disk(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path)
    disk = partition(
        "sdc", type="disk", fstype="exfat", uuid="C40C-B21F", label="GAMES"
    )
    script_tree(fake_runner, tree_with(disk))
    script_table(fake_runner)
    script_start(
        fake_runner, "steamos-mounter@dev-disk-by\\x2duuid-C40C\\x2dB21F.service"
    )

    result = run_cli(ctx, "add", "--device", "/dev/sdc")

    assert result.code == ExitCode.OK, result.err
    volume = config.load(ctx).volumes[0]
    assert (volume.name, volume.fstype) == ("GAMES", "exfat")


def test_a_loop_device_is_registrable(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path)
    uuid = "57965dd9-f51e-409a-bcb2-40b5787afd0b"
    loop = partition("loop0", type="loop", fstype="btrfs", uuid=uuid, label="SCRATCH")
    script_tree(fake_runner, tree_with(loop))
    script_table(fake_runner)
    script_start(
        fake_runner,
        "steamos-mounter@dev-disk-by\\x2duuid-57965dd9\\x2df51e\\x2d409a\\x2dbcb2"
        "\\x2d40b5787afd0b.service",
    )

    result = run_cli(ctx, "add", "--device", "/dev/loop0")

    assert result.code == ExitCode.OK, result.err
    assert config.load(ctx).volumes[0].name == "SCRATCH"


def test_a_label_without_registry_characters_falls_back(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path)
    stick = partition("sdc1", fstype="vfat", uuid="C40C-B21F", label="...")
    script_tree(fake_runner, tree_with(stick))
    script_table(fake_runner)
    script_start(
        fake_runner, "steamos-mounter@dev-disk-by\\x2duuid-C40C\\x2dB21F.service"
    )

    assert run_cli(ctx, "add", "--device", "/dev/sdc1").code == ExitCode.OK
    assert config.load(ctx).volumes[0].name == "vfat-C40C-B21F"


# --- add: arguments -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "code", "message"),
    [
        (("--device", "/dev/sdz9"), ExitCode.NOT_PRESENT, "/dev/sdz9 is not attached"),
        (
            ("--uuid", MEDIABOX_UUID.lower()),
            ExitCode.NOT_PRESENT,
            "no attached device has the UUID 01d95f1575592a30",
        ),
        (("--device", "sdb5"), ExitCode.USAGE, "sdb5 is not an absolute device path"),
        (
            ("--device", "/etc/passwd"),
            ExitCode.USAGE,
            "/etc/passwd is not a block device under /dev",
        ),
        (
            ("--device", "/dev/sdb5", "--name=-bad"),
            ExitCode.USAGE,
            "-bad is not a valid name",
        ),
        (
            ("--uuid", "C40C-B21F", "--drivers", "ntfs3"),
            ExitCode.REFUSED,
            "OS partition",
        ),
        (
            ("--device", "/dev/sdb5", "--drivers", "ntfs3,fuse"),
            ExitCode.USAGE,
            "--drivers: unknown token 'fuse'",
        ),
        (
            ("--device", "/dev/sdb5", "--drivers", "ntfs3,ntfs3"),
            ExitCode.USAGE,
            "--drivers: duplicate token",
        ),
    ],
    ids=[
        "absent",
        "uuid-not-exact",
        "relative",
        "not-dev",
        "bad-name",
        "refused-before-drivers",
        "unknown-driver",
        "duplicate-driver",
    ],
)
def test_add_argument_problems(ctx, host, fake_runner, argv, code, message):
    result = run_cli(ctx, "add", *argv)

    assert result.code == code
    assert message in result.err
    assert not registry_file(host).exists()
    assert systemctl_calls(fake_runner) == []


def test_drivers_only_for_ntfs_and_bitlocker(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path)
    stick = partition("sdc1", fstype="exfat", uuid="C40C-B21F", label="GAMES")
    script_tree(fake_runner, tree_with(stick))
    script_table(fake_runner)

    result = run_cli(ctx, "add", "--device", "/dev/sdc1", "--drivers", "ntfs3")

    assert result.code == ExitCode.USAGE
    assert "--drivers is only for ntfs and BitLocker volumes" in result.err


def test_add_refuses_with_an_unusable_registry(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path, registry=BROKEN_REGISTRY)

    result = run_cli(ctx, "add", "--device", "/dev/sdb5")

    assert result.code == ExitCode.FAILED
    assert result.err == (
        "steamos-mounter: the registry cannot be used. Fix it first: run"
        f" {CLI} doctor. {DETAILS}\n"
    )
    assert registry_bytes(tmp_path) == BROKEN_REGISTRY.encode()
    assert fake_runner.calls == []


# --- add: fixed paths (DD-31, DD-34) and the mount base -------------------------------


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("/mnt/X", "path must be directly under the mount base"),
        ("/home/deck/Drives/X", "path must be directly under the mount base"),
        ("/run/media/deck/STICK/sub/X", "path must be directly under the mount base"),
        ("/run/media/deck", "path is the mount base or one of its parents"),
        ("/etc/X", "path is at or under a system directory"),
    ],
    ids=["mnt", "home", "nested", "base", "etc"],
)
def test_add_refuses_a_path_outside_the_base(ctx, tmp_path, fake_runner, path, reason):
    given_host(ctx, tmp_path, registry=PERSONAL_REGISTRY)
    script_tree(fake_runner)
    script_table(fake_runner)
    before = registry_bytes(tmp_path)

    result = run_cli(ctx, "add", "--device", "/dev/sdb5", "--path", path)

    assert result.code == ExitCode.REFUSED
    assert result.err == (
        f"steamos-mounter: cannot register /dev/sdb5: {reason}. {DETAILS}\n"
    )
    assert registry_bytes(tmp_path) == before


def test_add_refuses_a_base_writable_by_others(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path)
    (tmp_path / "run/media/deck").chmod(0o770)
    script_tree(fake_runner)
    script_table(fake_runner)

    result = run_cli(ctx, "add", "--device", "/dev/sdb5")

    assert result.code == ExitCode.REFUSED
    assert "a parent directory is a symlink or writable by a non-root user" in (
        result.err
    )
    assert not registry_file(tmp_path).exists()


def test_add_refuses_a_symlinked_parent_into_a_system_directory(
    ctx, tmp_path, fake_runner
):
    given_host(ctx, tmp_path, mount_base=False)
    system = tmp_path / "usr/lib"
    system.mkdir(parents=True)
    (tmp_path / "run/media").symlink_to(system)
    script_tree(fake_runner)
    script_table(fake_runner)

    result = run_cli(ctx, "add", "--device", "/dev/sdb5")

    # ensure_mount_base refuses a parent that is not a real directory: exit 1.
    assert result.code == ExitCode.FAILED
    assert "cannot set up the mount base" in result.err
    assert list(system.iterdir()) == []
    assert not registry_file(tmp_path).exists()
    assert SETFACL not in [argv[0] for argv in fake_runner.argvs]


def test_add_on_a_fresh_run_creates_the_mount_base(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path, mount_base=False)
    script_tree(fake_runner)
    script_table(fake_runner)
    script_setfacl(fake_runner)
    script_start(fake_runner)

    result = run_cli(ctx, "add", "--device", "/dev/sdb5", "--name", "MEDIABOX")

    assert result.code == ExitCode.OK, result.err
    assert stat.S_IMODE(os.stat(tmp_path / "run/media").st_mode) == 0o755
    assert stat.S_IMODE(os.stat(tmp_path / "run/media/deck").st_mode) == 0o750
    assert [argv for argv in fake_runner.argvs if argv[0] == SETFACL] == [
        (SETFACL, "-m", "u:1000:r-x", "/run/media/deck")
    ]
    assert config.load(ctx).volumes[0].path == MEDIABOX_PATH


def test_a_present_base_is_left_alone(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path)
    (tmp_path / "run/media/deck").chmod(0o700)
    script_tree(fake_runner)
    script_table(fake_runner)
    script_start(fake_runner)

    assert run_cli(ctx, "add", "--device", "/dev/sdb5").code == ExitCode.OK
    assert stat.S_IMODE(os.stat(tmp_path / "run/media/deck").st_mode) == 0o700
    assert SETFACL not in [argv[0] for argv in fake_runner.argvs]


def test_a_failed_setfacl_exits_1_and_leaves_no_base(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path, mount_base=False)
    script_tree(fake_runner)
    script_setfacl(fake_runner, returncode=1)

    result = run_cli(ctx, "add", "--device", "/dev/sdb5")

    assert result.code == ExitCode.FAILED
    assert "cannot set up the mount base" in result.err
    assert not (tmp_path / "run/media/deck").exists()
    assert not registry_file(tmp_path).exists()


def test_add_refuses_the_path_of_a_current_auto_mount(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path)
    (tmp_path / "run/media/deck/GAMES").mkdir()  # empty, so rule 5 does not fire
    script_tree(fake_runner)
    script_table(
        fake_runner, Answer.from_fixture("findmnt-games-exfat-rw.json", returncode=0)
    )

    result = run_cli(
        ctx, "add", "--device", "/dev/sdb5", "--path", "/run/media/deck/GAMES"
    )

    assert result.code == ExitCode.REFUSED
    assert "path overlaps another registered path or mount" in result.err
    assert not registry_file(tmp_path).exists()


def test_add_refuses_a_name_or_path_that_is_taken(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path, registry=PERSONAL_REGISTRY)
    script_tree(fake_runner)
    script_table(fake_runner)

    by_name = run_cli(ctx, "add", "--device", "/dev/sdb5", "--name", "personal")
    by_path = run_cli(
        ctx, "add", "--device", "/dev/sdb5", "--path", "/run/media/deck/PERSONAL"
    )

    assert (by_name.code, by_path.code) == (ExitCode.REFUSED, ExitCode.REFUSED)
    assert "duplicate name" in by_name.err
    assert "path overlaps another registered path or mount" in by_path.err


# --- add: the BitLocker key (AC-011, AC-050, IP-10) -----------------------------------


@pytest.fixture
def bitlocker_host(ctx, tmp_path, fake_runner):
    given_host(ctx, tmp_path)
    make_keys_dir(tmp_path)
    script_tree(fake_runner)
    script_table(fake_runner)
    return tmp_path


def test_add_bitlocker_tests_then_stores_the_key(
    ctx, bitlocker_host, fake_runner, monkeypatch
):
    stdin_key(monkeypatch)
    fake_runner.on((*TEST_ARGV, "/dev/sdb1"), Answer())
    script_start(fake_runner, PERSONAL_UNIT)

    result = run_cli(
        ctx, "add", "--device", "/dev/sdb1", "--name", "PERSONAL", "--key-stdin"
    )

    assert result.code == ExitCode.OK, result.err
    key = bitlocker_host / PERSONAL_KEY
    assert key.read_bytes() == TEST_KEY
    assert stat.S_IMODE(os.lstat(key).st_mode) == 0o600
    tested = [call for call in fake_runner.calls if call.argv[0] == CRYPTSETUP]
    assert len(tested) == 1
    assert tested[0].secret_stdin
    assert tested[0].stdin == TEST_KEY
    volume = config.load(ctx).volumes[0]
    assert (volume.name, volume.fstype, volume.uuid) == (
        "PERSONAL",
        "BitLocker",
        PERSONAL_UUID,
    )


def test_add_bitlocker_key_from_a_file(ctx, bitlocker_host, fake_runner, tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_bytes(TEST_KEY + b"\r\n")
    fake_runner.on((*TEST_ARGV, "/dev/sdb1"), Answer())
    script_start(fake_runner, PERSONAL_UNIT)

    result = run_cli(ctx, "add", "--device", "/dev/sdb1", "--key-file", str(key_file))

    assert result.code == ExitCode.OK, result.err
    assert (bitlocker_host / PERSONAL_KEY).read_bytes() == TEST_KEY
    assert config.load(ctx).volumes[0].name == "PAT4T4SHUAWEI_PERSONAL_4_3_2024"


def test_add_bitlocker_key_from_the_hidden_prompt(
    ctx, bitlocker_host, fake_runner, monkeypatch
):
    prompts = []

    def prompt(text: str) -> str:
        prompts.append(text)
        return TEST_KEY.decode()

    monkeypatch.setattr("getpass.getpass", prompt)
    fake_runner.on((*TEST_ARGV, "/dev/sdb1"), Answer())
    script_start(fake_runner, PERSONAL_UNIT)

    result = run_cli(ctx, "add", "--device", "/dev/sdb1", "--name", "PERSONAL")

    assert result.code == ExitCode.OK, result.err
    assert prompts == ["BitLocker key for PERSONAL: "]
    assert (bitlocker_host / PERSONAL_KEY).read_bytes() == TEST_KEY


def test_wrong_key_refused_nothing_stored(
    ctx, bitlocker_host, fake_runner, monkeypatch
):
    stdin_key(monkeypatch)
    fake_runner.on((*TEST_ARGV, "/dev/sdb1"), Answer(returncode=2))

    result = run_cli(ctx, "add", "--device", "/dev/sdb1", "--key-stdin")

    assert result.code == ExitCode.REFUSED
    assert result.err == (
        f"steamos-mounter: the key was not accepted. Nothing was stored. {DETAILS}\n"
    )
    assert list((bitlocker_host / PERSONAL_KEY).parent.iterdir()) == []
    assert not registry_file(bitlocker_host).exists()
    assert systemctl_calls(fake_runner) == []


@pytest.mark.parametrize(
    "answer", [Answer(returncode=1), Answer.timeout(), Answer.missing()]
)
def test_a_key_check_that_fails_is_a_tool_error(
    ctx, bitlocker_host, fake_runner, monkeypatch, answer
):
    stdin_key(monkeypatch)
    fake_runner.on((*TEST_ARGV, "/dev/sdb1"), answer)

    result = run_cli(ctx, "add", "--device", "/dev/sdb1", "--key-stdin")

    assert result.code == ExitCode.FAILED
    assert "the key could not be checked: cryptsetup failed" in result.err
    assert list((bitlocker_host / PERSONAL_KEY).parent.iterdir()) == []
    assert not registry_file(bitlocker_host).exists()


def test_no_terminal_for_the_prompt_is_a_usage_error(
    ctx, bitlocker_host, fake_runner, monkeypatch
):
    def no_terminal(_text: str) -> str:
        raise OSError("no tty")

    monkeypatch.setattr("getpass.getpass", no_terminal)

    result = run_cli(ctx, "add", "--device", "/dev/sdb1")

    assert result.code == ExitCode.USAGE
    assert "Use --key-file PATH or --key-stdin" in result.err
    assert CRYPTSETUP not in [argv[0] for argv in fake_runner.argvs]


def test_a_refusal_comes_before_the_key_prompt(ctx, tmp_path, fake_runner, monkeypatch):
    given_host(ctx, tmp_path, registry=PERSONAL_REGISTRY)
    script_tree(fake_runner)
    monkeypatch.setattr("getpass.getpass", pytest.fail)

    result = run_cli(ctx, "add", "--device", "/dev/sdb1")

    assert result.code == ExitCode.REFUSED
    assert "already registered as PERSONAL" in result.err


# --- remove (AC-049, ADR-0004 D8) -----------------------------------------------------


def given_registered(ctx, root: Path, registry: str) -> None:
    given_host(ctx, root, registry=registry)
    wiring.sync_links(ctx, config.load(ctx))


def script_remove(fake_runner, unit: str, key_unit: str, *, key_state="inactive"):
    fake_runner.on(DAEMON_RELOAD, Answer(), repeat=True)
    script_unit(fake_runner, key_unit, key_state)
    fake_runner.on(verb_argv("stop", unit, block=True), Answer())


def test_remove_unwire_then_stop(ctx, tmp_path, fake_runner):
    given_registered(ctx, tmp_path, MEDIABOX_REGISTRY)
    write_record(
        tmp_path, MEDIABOX_RECORD, __import__("json").dumps(mediabox_record()).encode()
    )
    key_unit = MEDIABOX_UNIT.replace("steamos-mounter@", "steamos-mounter-key@")
    link_at_stop = []
    fake_runner.on(DAEMON_RELOAD, Answer(), repeat=True)
    script_unit(fake_runner, key_unit, "inactive")
    fake_runner.on(
        verb_argv("stop", MEDIABOX_UNIT, block=True),
        Answer(),
        hook=lambda _cmd: link_at_stop.append((tmp_path / MEDIABOX_LINK).is_symlink()),
    )

    result = run_cli(ctx, "remove", "MEDIABOX")

    assert (result.code, result.err) == (ExitCode.OK, "")
    assert result.out == "unwired MEDIABOX\nstopped MEDIABOX\nremoved MEDIABOX\n"
    assert link_at_stop == [False]
    assert systemctl_calls(fake_runner) == [
        DAEMON_RELOAD,
        show_argv(key_unit),
        verb_argv("stop", MEDIABOX_UNIT, block=True),
    ]
    assert config.load(ctx).volumes == ()
    assert registry_file(tmp_path).read_text(encoding="utf-8") == registry_text(())
    assert not (tmp_path / MEDIABOX_RECORD).exists()
    assert not (tmp_path / MEDIABOX_LINK).parent.exists()


def mediabox_record(**changes):
    return record_dict(
        key="01d95f1575592a30",
        name="MEDIABOX",
        unit=MEDIABOX_UNIT,
        mapping=None,
        **changes,
    )


def test_remove_bitlocker_stops_the_key_unit_and_deletes_the_key(
    ctx, tmp_path, fake_runner
):
    given_registered(ctx, tmp_path, PERSONAL_REGISTRY)
    write_key_file(tmp_path, PERSONAL_UUID, TEST_KEY)
    fake_runner.on(DAEMON_RELOAD, Answer(), repeat=True)
    script_unit(fake_runner, PERSONAL_KEY_UNIT, "active")
    fake_runner.on(verb_argv("stop", PERSONAL_KEY_UNIT, block=True), Answer())
    fake_runner.on(verb_argv("stop", PERSONAL_UNIT, block=True), Answer())

    result = run_cli(ctx, "remove", "personal")

    assert result.code == ExitCode.OK
    assert result.out.splitlines()[-1] == "removed PERSONAL and its key"
    stops = [argv for argv in systemctl_calls(fake_runner) if argv[1] == "stop"]
    assert stops == [
        verb_argv("stop", PERSONAL_KEY_UNIT, block=True),
        verb_argv("stop", PERSONAL_UNIT, block=True),
    ]
    assert not (tmp_path / PERSONAL_KEY).exists()


def test_remove_reports_busy_items_and_exits_6(ctx, tmp_path, fake_runner):
    given_registered(ctx, tmp_path, PERSONAL_REGISTRY)
    busy = [PERSONAL_PATH, f"steamos-mounter-{PERSONAL_UUID}"]
    write_record(
        tmp_path,
        PERSONAL_RECORD,
        __import__("json").dumps(record_dict(busy=busy)).encode(),
    )
    script_remove(fake_runner, PERSONAL_UNIT, PERSONAL_KEY_UNIT)

    result = run_cli(ctx, "remove", "PERSONAL")

    assert result.code == ExitCode.BUSY
    assert result.out.splitlines()[-2:] == [
        f"busy: {item} is released once nothing uses it any more" for item in busy
    ]
    assert not (tmp_path / PERSONAL_RECORD).exists()


def test_remove_of_an_unknown_name_exits_2(ctx, tmp_path, fake_runner):
    given_registered(ctx, tmp_path, MEDIABOX_REGISTRY)

    result = run_cli(ctx, "remove", "GAMES")

    assert result.code == ExitCode.USAGE
    assert result.err == (
        f"steamos-mounter: no registered volume is called GAMES. {DETAILS}\n"
    )
    assert fake_runner.calls == []
    assert (tmp_path / MEDIABOX_LINK).is_symlink()


def test_a_stop_that_fails_keeps_the_entry(ctx, tmp_path, fake_runner):
    given_registered(ctx, tmp_path, MEDIABOX_REGISTRY)
    key_unit = MEDIABOX_UNIT.replace("steamos-mounter@", "steamos-mounter-key@")
    fake_runner.on(DAEMON_RELOAD, Answer(), repeat=True)
    script_unit(fake_runner, key_unit, "inactive")
    fake_runner.on(verb_argv("stop", MEDIABOX_UNIT, block=True), Answer.timeout())

    result = run_cli(ctx, "remove", "MEDIABOX")

    assert result.code == ExitCode.FAILED
    assert "MEDIABOX could not be stopped. Run remove again" in result.err
    assert config.load(ctx).by_name("MEDIABOX") is not None
    assert not (tmp_path / MEDIABOX_LINK).exists()  # unwired first, as D8 says


def test_remove_rewires_when_the_registry_changed_meanwhile(ctx, tmp_path, fake_runner):
    """Another ``add`` between the unwire and the write: its link is kept."""
    given_registered(ctx, tmp_path, MEDIABOX_REGISTRY)
    key_unit = MEDIABOX_UNIT.replace("steamos-mounter@", "steamos-mounter-key@")
    fake_runner.on(DAEMON_RELOAD, Answer(), repeat=True)
    script_unit(fake_runner, key_unit, "inactive")

    def add_personal(_command) -> None:
        config.update(ctx, lambda current: config.with_volume(current, personal()))

    fake_runner.on(
        verb_argv("stop", MEDIABOX_UNIT, block=True), Answer(), hook=add_personal
    )

    assert run_cli(ctx, "remove", "MEDIABOX").code == ExitCode.OK
    assert [volume.name for volume in config.load(ctx).volumes] == ["PERSONAL"]
    assert sorted(wiring.existing_links(ctx)) == sorted(
        wiring.expected_links(config.load(ctx))
    )
    assert systemctl_calls(fake_runner).count(DAEMON_RELOAD) == 2


def personal():
    from steamos_mounter.model import Volume

    return Volume(
        name=PERSONAL.name,
        uuid=PERSONAL.uuid,
        path=PERSONAL.path,
        fstype=PERSONAL.fstype,
        drivers=None,
        nosuid=True,
        nodev=True,
    )


# --- add and remove never rewrite a registry with invalid entries -----------------
# Owner decision 2026-10-11: the emitter writes only valid entries, so a rewrite
# would silently drop a hand-edited entry with a mistake.

GAMES_INVALID = """
[[volume]]
name = "GAMES"
uuid = "1234-ABCD"
path = "/mnt/GAMES"
fstype = "exfat"
nosuid = true
nodev = true
"""
INVALID_ENTRY_REFUSED = (
    "steamos-mounter: the registry has an invalid entry: [[volume]] number 2."
    " Fix or remove it in /etc/steamos-mounter/config.toml first."
    f" {DETAILS}\n"
)


def wiring_snapshot(root: Path) -> list[tuple[str, str]]:
    """Every path under the wiring directory, with a link's target."""
    wants = root / SYSTEMD_SYSTEM
    return [
        (name, os.readlink(wants / name) if (wants / name).is_symlink() else "")
        for name in files_under(wants)
    ]


@pytest.mark.parametrize(
    ("registered", "device"),
    [(PERSONAL_REGISTRY, "/dev/sdb5"), (MEDIABOX_REGISTRY, "/dev/sdb1")],
    ids=["ntfs", "bitlocker"],
)
def test_add_refuses_a_registry_with_an_invalid_entry(
    ctx, tmp_path, fake_runner, monkeypatch, registered, device
):
    given_registered(ctx, tmp_path, registered + GAMES_INVALID)
    script_tree(fake_runner)
    script_table(fake_runner)
    monkeypatch.setattr("getpass.getpass", pytest.fail)
    before = registry_bytes(tmp_path)
    links = wiring_snapshot(tmp_path)

    result = run_cli(ctx, "add", "--device", device)

    assert (result.code, result.out) == (ExitCode.FAILED, "")
    assert result.err == INVALID_ENTRY_REFUSED
    assert registry_bytes(tmp_path) == before
    assert wiring_snapshot(tmp_path) == links
    assert systemctl_calls(fake_runner) == []
    assert CRYPTSETUP not in [argv[0] for argv in fake_runner.argvs]


@pytest.mark.parametrize("name", ["MEDIABOX", "GAMES"])
def test_remove_refuses_a_registry_with_an_invalid_entry(
    ctx, tmp_path, fake_runner, name
):
    given_registered(ctx, tmp_path, MEDIABOX_REGISTRY + GAMES_INVALID)
    before = registry_bytes(tmp_path)
    links = wiring_snapshot(tmp_path)

    result = run_cli(ctx, "remove", name)

    assert (result.code, result.out) == (ExitCode.FAILED, "")
    assert result.err == INVALID_ENTRY_REFUSED
    assert registry_bytes(tmp_path) == before
    assert wiring_snapshot(tmp_path) == links
    assert (tmp_path / MEDIABOX_LINK).is_symlink()
    assert fake_runner.calls == []


def test_the_refusal_journals_each_entry_reason(ctx, tmp_path, fake_runner, caplog):
    given_registered(ctx, tmp_path, MEDIABOX_REGISTRY + GAMES_INVALID)

    run_cli(ctx, "remove", "MEDIABOX")

    assert (
        "registry not rewritten: [[volume]] number 2:"
        " path must be directly under the mount base"
    ) in caplog.text


@pytest.mark.parametrize(
    "pasted",
    [
        "123456-234567-345678-456789-567890-678901-789012-890123",
        "Tr0ub4dor-And-Correct-Horse-Battery-Staple-9xQ",
    ],
    ids=["recovery-key", "mixed-case"],
)
def test_a_key_pasted_as_a_toml_key_never_reaches_the_journal_or_terminal(
    ctx, tmp_path, fake_runner, caplog, pasted
):
    broken = MEDIABOX_REGISTRY + GAMES_INVALID.replace(
        'path = "/mnt/GAMES"', f'path = "/run/media/deck/GAMES"\n{pasted} = true'
    )
    given_registered(ctx, tmp_path, broken)
    caplog.set_level(logging.DEBUG)

    result = run_cli(ctx, "remove", "MEDIABOX")

    shown = pasted in result.out + result.err
    journaled = pasted in caplog.text
    assert result.code == ExitCode.FAILED
    assert "registry not rewritten: [[volume]] number 2: unknown key" in caplog.text
    assert not shown
    assert not journaled


RECOVERY_KEY = "123456-234567-345678-456789-567890-678901-789012-890123"


@pytest.mark.parametrize(
    "top",
    [f"{RECOVERY_KEY} = true", f"x = {{{RECOVERY_KEY} = 1, {RECOVERY_KEY} = 2}}"],
    ids=["top-level-key", "toml-error"],
)
def test_a_key_pasted_into_an_unusable_registry_is_never_journaled_or_shown(
    ctx, tmp_path, fake_runner, caplog, top
):
    top_level = MEDIABOX_REGISTRY.replace("\n\n", f"\n{top}\n\n", 1)
    given_host(ctx, tmp_path, registry=top_level)
    caplog.set_level(logging.DEBUG)

    result = run_cli(ctx, "remove", "MEDIABOX")

    shown = RECOVERY_KEY in result.out + result.err
    journaled = RECOVERY_KEY in caplog.text
    assert result.code == ExitCode.FAILED
    assert "the registry cannot be used" in result.err
    assert not shown
    assert not journaled
