"""The mounter: option table, argv builders, mount base, chain and unmount.

Design Doc "NTFS Chain, Mount Options and Read-back" ("Step Invocation",
"Mount Options per Driver", "Read-back and State"), "Teardown" (timeouts),
DD-25, DD-26, IP-07 to IP-09, IP-17, and ADR-0003 Decisions 2 to 7. Every
chain runs against the fake runner; the read-backs are the synthetic
``findmnt`` files until V-11 captures replace them. Two chains replay what
the owner saw on the Deck on 2026-10-09:

- MEDIABOX: probe 0, ``ntfs3`` rw refused with the real kernel line
  ``volume is dirty and "force" flag is not set!``, then ``ntfs-3g`` rw
  mounts: ``MountedRWDirty`` with reason ``dirty``.
- PERSONAL (inner ``dm-0``): probe 13 with "$MFTMirr does not match $MFT
  (record 3).", so the guard skips ``ntfs3`` rw; ``ntfs-3g`` rw refuses,
  ``ntfs3`` ro mounts: ``MountedRO`` with reason ``unsafe``, whose next step
  is a full Windows shutdown and ``chkdsk /f``.
"""

import dataclasses
import json
import os
import stat
from pathlib import Path

import pytest

from steamos_mounter import mountdirs, mounter, state
from steamos_mounter.blockdev import BlockDevice
from steamos_mounter.errors import MounterError, RefusedError, ToolError
from steamos_mounter.model import Driver, Mode, Step, VolumeState
from steamos_mounter.mounter import (
    LAZY_UNMOUNT_TIMEOUT,
    NORMAL_UNMOUNT_TIMEOUT,
    STEP_TIMEOUT,
    ChainResult,
    StepOutcome,
    UnmountResult,
    ensure_mount_base,
    options_for,
    prepare_target,
    run_chain,
    step_argv,
    unmount,
)
from steamos_mounter.mounts import FINDMNT_COLUMNS
from steamos_mounter.platforms.base import SessionUser
from steamos_mounter.platforms.steamos import TOOLS
from tests.helpers.fake_kmsg import kernel_messages
from tests.helpers.fake_platform import DECK_SESSION
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture

MOUNT = "/usr/bin/mount"
UMOUNT = "/usr/bin/umount"
NTFS3G = "/usr/bin/ntfs-3g"
PROBE = "/usr/bin/ntfs-3g.probe"
FINDMNT = "/usr/bin/findmnt"
SETFACL = "/usr/bin/setfacl"

NTFS3_RW = Step(Driver.NTFS3, Mode.RW)
NTFS3_RO = Step(Driver.NTFS3, Mode.RO)
NTFS3G_RW = Step(Driver.NTFS3G, Mode.RW)
NTFS3G_RO = Step(Driver.NTFS3G, Mode.RO)
NTFS_RW = Step(Driver.NTFS, Mode.RW)

NTFS_RW_OPTIONS = "nosuid,nodev,uid=1000,gid=1000,umask=0022,windows_names"
NTFS_RO_OPTIONS = "ro," + NTFS_RW_OPTIONS
FORBIDDEN = ("noexec", "force", "remove_hiberfile")

MEDIABOX_TARGET = "/run/media/deck/MEDIABOX"
NOT_BASE_CHILD = "path must be directly under the mount base"
PERSONAL_TARGET = "/run/media/deck/PERSONAL"
GAMES_TARGET = "/run/media/deck/GAMES"
PERSONAL_MAPPER = "/dev/mapper/steamos-mounter-658207d5-5177-4a52-a297-31643c64724d"
MFTMIRR_STDERR = b"$MFTMirr does not match $MFT (record 3).\n"
MOUNT_WRONG_FS = (
    b"mount: /run/media/deck/MEDIABOX: wrong fs type, bad option, bad superblock"
    b" on /dev/sdb5, missing codepage or helper program, or other error.\n"
    b"       dmesg(1) may have more information after failed mount system call.\n"
)
MOUNT_WRONG_FS_LINE = (
    "mount: /run/media/deck/MEDIABOX: wrong fs type, bad option, bad superblock"
    " on /dev/sdb5, missing codepage or helper program, or other error."
)
KERNEL_DIRTY = 'volume is dirty and "force" flag is not set!'
UMOUNT_BUSY = b"umount: /run/media/deck/MEDIABOX: target is busy.\n"


def block_device(kname: str, path: str, devnum: str, fstype: str) -> BlockDevice:
    return BlockDevice(
        kname=kname,
        path=path,
        devnum=devnum,
        type="part",
        fstype=fstype,
        label=None,
        uuid=None,
        partuuid=None,
        pkname=None,
        hotplug=True,
        ro=False,
        size=0,
        mountpoints=(),
        tran="usb",
    )


# Device numbers and paths as lsblk-full-bytes.json shows them on the Deck.
MEDIABOX = block_device("sdb5", "/dev/sdb5", "8:21", "ntfs")
PERSONAL = block_device("dm-0", PERSONAL_MAPPER, "252:0", "ntfs")
GAMES = block_device("sdc1", "/dev/sdc1", "8:33", "exfat")

NOT_MOUNTED = Answer.from_fixture("findmnt-sdb5-not-mounted.json")
MEDIABOX_FUSE_RW = Answer.from_fixture("findmnt-mediabox-fuseblk-rw.json", returncode=0)
MEDIABOX_FUSE_RO = Answer.from_fixture("findmnt-fuseblk-ro.json", returncode=0)
PERSONAL_NTFS3_RW = Answer.from_fixture("findmnt-personal-ntfs3-rw.json", returncode=0)
GAMES_EXFAT_RW = Answer.from_fixture("findmnt-games-exfat-rw.json", returncode=0)


def read_only(fixture: str) -> Answer:
    """A synthetic rw read-back turned read-only: ``rw`` -> ``ro`` in both lists."""
    document = json.loads(load_fixture(fixture))
    for row in document["filesystems"]:
        for key in ("vfs-options", "fs-options"):
            options = row[key].split(",")
            row[key] = ",".join(["ro", *options[1:]])
    return Answer(stdout=json.dumps(document).encode(), returncode=0)


PERSONAL_NTFS3_RO = read_only("findmnt-personal-ntfs3-rw.json")


def readback(target: str) -> tuple[str, ...]:
    return (FINDMNT, "--json", "-o", FINDMNT_COLUMNS, "--mountpoint", target)


def probe_answer(code: int, stderr: bytes = b"") -> Answer:
    return Answer(returncode=code, stderr=stderr)


def refused(code: int = 32, stderr: bytes = b"") -> Answer:
    return Answer(returncode=code, stderr=stderr)


def chain(ctx, device, target, **overrides) -> ChainResult:
    arguments = {
        "device": device,
        "target": target,
        "fstype": "ntfs",
        "steps": None,
        "nosuid": True,
        "nodev": True,
        "deadline": ctx.clock.monotonic() + 60.0,
    }
    arguments.update(overrides)
    return run_chain(ctx, **arguments)


def kernel_argv(driver: str, options: str, device: str, target: str):
    return (MOUNT, "-i", "-t", driver, "-o", options, device, target)


def ntfs3g_argv(options: str, device: str, target: str):
    return (NTFS3G, "-o", options, device, target)


def mount_tool_argvs(fake_runner) -> list[tuple[str, ...]]:
    return [argv for argv in fake_runner.argvs if argv[0] in {MOUNT, NTFS3G}]


def every_option_in(argvs) -> list[str]:
    options = []
    for argv in argvs:
        if "-o" in argv:
            options.extend(argv[argv.index("-o") + 1].split(","))
    return options


# --- options per driver ------------------------------------------------------


@pytest.mark.parametrize(
    ("driver", "mode", "expected"),
    [
        (Driver.NTFS3, Mode.RW, NTFS_RW_OPTIONS),
        (Driver.NTFS3, Mode.RO, NTFS_RO_OPTIONS),
        (Driver.NTFS3G, Mode.RW, NTFS_RW_OPTIONS),
        (Driver.NTFS3G, Mode.RO, NTFS_RO_OPTIONS),
        (Driver.NTFS, Mode.RW, "nosuid,nodev,uid=1000,gid=1000,umask=0022"),
        (Driver.NTFS, Mode.RO, "ro,nosuid,nodev,uid=1000,gid=1000,umask=0022"),
        (
            Driver.EXFAT,
            Mode.RW,
            "nosuid,nodev,uid=1000,gid=1000,umask=0022,iocharset=utf8,"
            "errors=remount-ro",
        ),
        (
            Driver.VFAT,
            Mode.RW,
            "nosuid,nodev,uid=1000,gid=1000,umask=0022,shortname=mixed,utf8,flush",
        ),
        (Driver.BTRFS, Mode.RW, "nosuid,nodev"),
    ],
)
def test_options_per_driver(driver, mode, expected):
    """The Design Doc table, with the Deck's session user (uid and gid 1000)."""
    options = options_for(driver, mode, DECK_SESSION, nosuid=True, nodev=True)

    assert ",".join(options) == expected


def test_options_take_uid_and_gid_from_the_session_user():
    user = SessionUser(
        name="other", uid=1001, gid=1002, runtime_dir="/run/user/1001", bus_address=""
    )

    options = options_for(Driver.NTFS3, Mode.RW, user, nosuid=True, nodev=True)

    assert "uid=1001" in options
    assert "gid=1002" in options


@pytest.mark.parametrize(
    ("nosuid", "nodev", "expected"),
    [
        (False, True, ("nodev",)),
        (True, False, ("nosuid",)),
        (False, False, ()),
    ],
)
def test_opt_out_drops_exactly_one_option(nosuid, nodev, expected):
    options = options_for(
        Driver.BTRFS, Mode.RW, DECK_SESSION, nosuid=nosuid, nodev=nodev
    )

    assert options == expected


def test_opt_out_keeps_the_rest_of_the_ntfs_set():
    options = options_for(Driver.NTFS3, Mode.RW, DECK_SESSION, nosuid=False, nodev=True)

    assert ",".join(options) == "nodev,uid=1000,gid=1000,umask=0022,windows_names"


@pytest.mark.parametrize("driver", [Driver.EXFAT, Driver.VFAT, Driver.BTRFS])
def test_read_only_options_refused_for_non_ntfs(driver):
    """Non-NTFS filesystems get one read-write step; "ro options: not used"."""
    with pytest.raises(ValueError, match="read-only"):
        options_for(driver, Mode.RO, DECK_SESSION, nosuid=True, nodev=True)


@pytest.mark.parametrize("driver", list(Driver))
@pytest.mark.parametrize("mode", list(Mode))
@pytest.mark.parametrize("nosuid", [True, False])
@pytest.mark.parametrize("nodev", [True, False])
def test_no_noexec_anywhere(driver, mode, nosuid, nodev):
    """AC-079, NFR-11: no option set ever holds noexec, force or remove_hiberfile."""
    try:
        options = options_for(driver, mode, DECK_SESSION, nosuid=nosuid, nodev=nodev)
    except ValueError:
        return  # a read-only step of a non-NTFS driver does not exist
    assert not set(options) & set(FORBIDDEN)
    assert not [option for option in options if option.split("=")[0] in FORBIDDEN]


# --- argv builders -----------------------------------------------------------


def test_kernel_step_argv_uses_mount_internal_only():
    """ADR-0003 Decision 2: ``mount -i -t <type>``, never a mount.<type> helper."""
    options = options_for(Driver.NTFS3, Mode.RW, DECK_SESSION, nosuid=True, nodev=True)

    argv = step_argv(TOOLS, NTFS3_RW, "/dev/sdb5", MEDIABOX_TARGET, options)

    assert argv == kernel_argv("ntfs3", NTFS_RW_OPTIONS, "/dev/sdb5", MEDIABOX_TARGET)


def test_kernel_ntfs_step_argv_has_internal_only_flag():
    options = options_for(Driver.NTFS, Mode.RW, DECK_SESSION, nosuid=True, nodev=True)

    argv = step_argv(TOOLS, NTFS_RW, "/dev/sdb5", MEDIABOX_TARGET, options)

    assert argv[:4] == (MOUNT, "-i", "-t", "ntfs")


def test_ntfs3g_step_argv_runs_the_binary_directly():
    options = options_for(Driver.NTFS3G, Mode.RO, DECK_SESSION, nosuid=True, nodev=True)

    argv = step_argv(TOOLS, NTFS3G_RO, "/dev/sdb5", MEDIABOX_TARGET, options)

    assert argv == ntfs3g_argv(NTFS_RO_OPTIONS, "/dev/sdb5", MEDIABOX_TARGET)


def test_kernel_step_without_options_has_no_dash_o():
    argv = step_argv(
        TOOLS, Step(Driver.BTRFS, Mode.RW), "/dev/sdc1", "/run/media/deck/DATA", ()
    )

    assert argv == (MOUNT, "-i", "-t", "btrfs", "/dev/sdc1", "/run/media/deck/DATA")


@pytest.mark.parametrize(
    ("device", "target"),
    [("sdb5", MEDIABOX_TARGET), ("/dev/sdb5", "run/media/deck/MEDIABOX")],
)
def test_step_argv_refuses_relative_positionals(device, target):
    """Both positionals start with ``/``, so neither can be read as an option."""
    with pytest.raises(ValueError, match="absolute"):
        step_argv(TOOLS, NTFS3_RW, device, target, ("nosuid",))


@pytest.mark.parametrize(
    "option", ["noexec", "force", "remove_hiberfile", "recover", "uid=abc", "a,b"]
)
def test_step_argv_refuses_options_outside_the_table(option):
    with pytest.raises(ValueError, match="option"):
        step_argv(TOOLS, NTFS3_RW, "/dev/sdb5", MEDIABOX_TARGET, ("nosuid", option))


def test_step_argv_refuses_ownership_options_for_btrfs():
    """btrfs uses on-disk ownership (AC-036): no uid= or gid=."""
    with pytest.raises(ValueError, match="option"):
        step_argv(
            TOOLS, Step(Driver.BTRFS, Mode.RW), "/dev/sdc1", GAMES_TARGET, ("uid=1000",)
        )


# --- run_chain: the real Deck cases ------------------------------------------


def test_clean_ntfs_ntfs3_rw(ctx, fake_runner):
    """AC-015: clean NTFS mounts read-write with ntfs3 and nothing else runs."""
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback(PERSONAL_TARGET), PERSONAL_NTFS3_RW)

    result = chain(ctx, PERSONAL, PERSONAL_TARGET)

    assert result.state is VolumeState.MOUNTED_RW
    assert result.driver == "ntfs3"
    assert result.reason == ""
    assert result.mounted is not None
    assert result.mounted.source == PERSONAL_MAPPER
    assert result.outcomes == (StepOutcome(NTFS3_RW, "mounted", ""),)
    assert fake_runner.argvs == [
        (PROBE, "--readwrite", "/dev/dm-0"),
        kernel_argv("ntfs3", NTFS_RW_OPTIONS, "/dev/dm-0", PERSONAL_TARGET),
        readback(PERSONAL_TARGET),
    ]


def test_dirty_ntfs3g_rw(ctx, fake_runner, fake_kmsg):
    """The real MEDIABOX case: probe 0, kernel refuses dirty, ntfs-3g mounts rw."""
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, refused(32, MOUNT_WRONG_FS))
    fake_runner.on(NTFS3G, Answer())
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, MEDIABOX_FUSE_RW)
    fake_kmsg.queue(*kernel_messages("sdb5")[:2])

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert result.state is VolumeState.MOUNTED_RW_DIRTY
    assert result.driver == "ntfs-3g"
    assert result.reason == "dirty"
    assert result.outcomes == (
        StepOutcome(NTFS3_RW, "refused", KERNEL_DIRTY),
        StepOutcome(NTFS3G_RW, "mounted", ""),
    )
    assert mount_tool_argvs(fake_runner) == [
        kernel_argv("ntfs3", NTFS_RW_OPTIONS, "/dev/sdb5", MEDIABOX_TARGET),
        ntfs3g_argv(NTFS_RW_OPTIONS, "/dev/sdb5", MEDIABOX_TARGET),
    ]


def test_dirty_ntfs3g_rw_from_probe_15(ctx, fake_runner):
    """Probe 15 (unclean $LogFile) alone makes an ntfs-3g rw mount dirty."""
    fake_runner.on(PROBE, probe_answer(15))
    fake_runner.on(MOUNT, refused(32))
    fake_runner.on(NTFS3G, Answer())
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, MEDIABOX_FUSE_RW)

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert (result.state, result.reason) == (VolumeState.MOUNTED_RW_DIRTY, "dirty")


def test_dirty_ntfs3g_rw_from_the_fixing_message(ctx, fake_runner):
    """ntfs-3g saying it reset the journal is dirty evidence of its own."""
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, refused(32))
    fake_runner.on(
        NTFS3G, Answer(stderr=load_fixture("ntfs3g-stderr-dirty-fixing.txt"))
    )
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, MEDIABOX_FUSE_RW)

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert (result.state, result.reason) == (VolumeState.MOUNTED_RW_DIRTY, "dirty")
    assert result.outcomes[-1] == StepOutcome(
        NTFS3G_RW, "mounted", "The file system wasn't safely closed on Windows. Fixing."
    )


def test_ntfs3g_rw_without_dirty_evidence_is_rw_with_a_reason(ctx, fake_runner):
    """NFR-14: rw via ntfs-3g for any other reason is MountedRW naming it."""
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, refused(32, MOUNT_WRONG_FS))
    fake_runner.on(NTFS3G, Answer())
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, MEDIABOX_FUSE_RW)

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert result.state is VolumeState.MOUNTED_RW
    assert result.driver == "ntfs-3g"
    assert result.reason == MOUNT_WRONG_FS_LINE


def test_personal_probe_13_ends_ro_with_a_chkdsk_next_step(ctx, fake_runner):
    """The real PERSONAL case of 2026-10-09 (owner rule I006)."""
    fake_runner.on(PROBE, probe_answer(13, MFTMIRR_STDERR))
    fake_runner.on(NTFS3G, refused(13, MFTMIRR_STDERR))
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback(PERSONAL_TARGET), NOT_MOUNTED, PERSONAL_NTFS3_RO)

    result = chain(ctx, PERSONAL, PERSONAL_TARGET)

    assert result.state is VolumeState.MOUNTED_RO
    assert result.driver == "ntfs3"
    assert result.reason == "unsafe"
    assert result.outcomes == (
        StepOutcome(NTFS3_RW, "skipped", "probe: unsafe"),
        StepOutcome(NTFS3G_RW, "refused", "$MFTMirr does not match $MFT (record 3)."),
        StepOutcome(NTFS3_RO, "mounted", ""),
    )
    assert mount_tool_argvs(fake_runner) == [
        ntfs3g_argv(NTFS_RW_OPTIONS, "/dev/dm-0", PERSONAL_TARGET),
        kernel_argv("ntfs3", NTFS_RO_OPTIONS, "/dev/dm-0", PERSONAL_TARGET),
    ]
    step = state.next_step(
        result.state, result.reason, name="PERSONAL", cli_root="sudo steamos-mounter"
    )
    assert "chkdsk /f" in step


def test_unsafe_ends_ro(ctx, fake_runner):
    """AC-017, AC-069, R-19: probe 14 skips ntfs3 rw; ntfs-3g falls back to ro."""
    fake_runner.on(PROBE, probe_answer(14))
    fake_runner.on(NTFS3G, Answer(stderr=load_fixture("ntfs3g-stderr-unsafe.txt")))
    fake_runner.on(readback(MEDIABOX_TARGET), MEDIABOX_FUSE_RO)

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert result.state is VolumeState.MOUNTED_RO
    assert result.driver == "ntfs-3g"
    assert result.reason == "unsafe"
    assert result.outcomes[0] == StepOutcome(NTFS3_RW, "skipped", "probe: unsafe")
    assert result.outcomes[1].result == "mounted"
    assert not [argv for argv in fake_runner.argvs if argv[0] == MOUNT]
    warning = state.warning(result.state, result.reason, name="MEDIABOX")
    assert warning is not None
    assert "unsafe state (hibernation, Fast Startup, or an abrupt unplug)" in warning


@pytest.mark.parametrize(
    "probe",
    [probe_answer(14), probe_answer(13), Answer.missing(), Answer.timeout()],
)
def test_unsafe_probe_never_runs_a_kernel_rw_step(ctx, fake_runner, probe):
    """R-19 is blocking: no kernel rw step on any unsafe probe result."""
    fake_runner.on(PROBE, probe)
    fake_runner.on(NTFS3G, refused(14))
    fake_runner.on(MOUNT, refused(32))
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, repeat=True)

    chain(
        ctx, MEDIABOX, MEDIABOX_TARGET, steps=(NTFS3_RW, NTFS_RW, NTFS3G_RW, NTFS3_RO)
    )

    kernel_modes = [
        argv[5].split(",")[0] for argv in fake_runner.argvs if argv[0] == MOUNT
    ]
    assert kernel_modes == ["ro"]


def test_ntfs3g_only_list_unsafe_ends_ro(ctx, fake_runner):
    """``drivers = ["ntfs-3g"]`` on an unsafe volume: ro through ntfs-3g itself."""
    fake_runner.on(PROBE, probe_answer(14))
    fake_runner.on(NTFS3G, Answer(stderr=load_fixture("ntfs3g-stderr-unsafe.txt")))
    fake_runner.on(readback(MEDIABOX_TARGET), MEDIABOX_FUSE_RO)

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET, steps=(NTFS3G_RW,))

    assert (result.state, result.driver, result.reason) == (
        VolumeState.MOUNTED_RO,
        "ntfs-3g",
        "unsafe",
    )
    assert len(result.outcomes) == 1
    assert result.outcomes[0].result == "mounted"
    assert "unsafe state" in result.outcomes[0].detail


def test_all_steps_fail_no_extra_driver(ctx, fake_runner, fake_kmsg):
    """AC-018, NFR-13: every step fails -> MountFailed; nothing outside the chain."""
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, refused(32), refused(32))
    fake_runner.on(NTFS3G, refused(21))
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, repeat=True)
    fake_kmsg.queue(f"ntfs3(sdb5): {KERNEL_DIRTY}")

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert result.state is VolumeState.MOUNT_FAILED
    assert result.mounted is None
    assert result.driver is None
    assert result.reason == "dirty"
    assert [outcome.result for outcome in result.outcomes] == ["refused"] * 3
    assert [outcome.step for outcome in result.outcomes] == [
        NTFS3_RW,
        NTFS3G_RW,
        NTFS3_RO,
    ]
    assert mount_tool_argvs(fake_runner) == [
        kernel_argv("ntfs3", NTFS_RW_OPTIONS, "/dev/sdb5", MEDIABOX_TARGET),
        ntfs3g_argv(NTFS_RW_OPTIONS, "/dev/sdb5", MEDIABOX_TARGET),
        kernel_argv("ntfs3", NTFS_RO_OPTIONS, "/dev/sdb5", MEDIABOX_TARGET),
    ]
    assert {argv[0] for argv in fake_runner.argvs} == {PROBE, MOUNT, NTFS3G, FINDMNT}


def test_drivers_list_runs_only_its_steps_in_order(ctx, fake_runner):
    """AC-019: a ro-only list needs no probe and runs exactly its steps."""
    fake_runner.on(NTFS3G, refused(21))
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback(PERSONAL_TARGET), NOT_MOUNTED, PERSONAL_NTFS3_RO)

    result = chain(ctx, PERSONAL, PERSONAL_TARGET, steps=(NTFS3G_RO, NTFS3_RO))

    assert result.state is VolumeState.MOUNTED_RO
    assert result.reason == "unknown"
    assert [argv[0] for argv in fake_runner.argvs] == [NTFS3G, FINDMNT, MOUNT, FINDMNT]


def test_held_probe_mounts_nothing(ctx, fake_runner):
    """AC-034: probe 16 -> MountedElsewhere reason held; no step runs."""
    fake_runner.on(PROBE, probe_answer(16))

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert (result.state, result.reason) == (VolumeState.MOUNTED_ELSEWHERE, "held")
    assert [outcome.result for outcome in result.outcomes] == ["skipped"] * 3
    assert fake_runner.argvs == [(PROBE, "--readwrite", "/dev/sdb5")]


def test_chain_result_carries_the_probe_for_the_record(ctx, fake_runner):
    """reconcile writes ``attempt.probe`` from the result; the chain ran the probe."""
    fake_runner.on(PROBE, probe_answer(15))
    fake_runner.on(MOUNT, refused(32))
    fake_runner.on(NTFS3G, Answer())
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, MEDIABOX_FUSE_RW)

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert result.probe is not None
    assert (result.probe.code, result.probe.klass) == (15, "dirty")


def test_chain_result_carries_the_probe_when_nothing_mounted(ctx, fake_runner):
    fake_runner.on(PROBE, probe_answer(16))

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert result.probe is not None
    assert result.probe.code == 16


def test_chain_result_has_no_probe_without_one(ctx, fake_runner):
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback(GAMES_TARGET), GAMES_EXFAT_RW)

    result = chain(ctx, GAMES, GAMES_TARGET, fstype="exfat")

    assert result.probe is None


def test_rw_request_ro_result_reported_ro(ctx, fake_runner):
    """AC-063, A-11: the mode comes from findmnt, not from the request."""
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(NTFS3G, Answer(stderr=load_fixture("ntfs3g-stderr-unsafe.txt")))
    fake_runner.on(readback(MEDIABOX_TARGET), MEDIABOX_FUSE_RO)

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET, steps=(NTFS3G_RW,))

    assert result.state is VolumeState.MOUNTED_RO
    assert result.reason == "unsafe"
    assert result.mounted is not None
    assert result.mounted.read_only


def test_kernel_rw_request_with_ro_read_back_is_ro(ctx, fake_runner):
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback(PERSONAL_TARGET), PERSONAL_NTFS3_RO)

    result = chain(ctx, PERSONAL, PERSONAL_TARGET)

    assert (result.state, result.driver) == (VolumeState.MOUNTED_RO, "ntfs3")
    assert result.reason == "unknown"


def test_exit_zero_without_a_mount_is_a_failure(ctx, fake_runner):
    """ADR-0003 Decision 6: exit 0 but nothing at the target -> next step."""
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(NTFS3G, Answer())
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, MEDIABOX_FUSE_RW)

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert result.outcomes[0] == StepOutcome(
        NTFS3_RW, "refused", "exit 0 but nothing mounted"
    )
    assert result.driver == "ntfs-3g"


def test_mount_of_another_device_at_the_target_does_not_count(ctx, fake_runner):
    """Read-back must name this device (MAJ:MIN or source), not just the target."""
    other = Answer.from_fixture("findmnt-ntfs-rw.json", returncode=0)
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback(MEDIABOX_TARGET), other)

    stick = dataclasses.replace(GAMES, fstype="ntfs")

    result = chain(ctx, stick, MEDIABOX_TARGET, steps=(NTFS3_RO,))

    assert result.state is VolumeState.MOUNT_FAILED
    assert result.outcomes[0].result == "refused"


def test_ntfs3g_timeout_is_no_reason_of_its_own(ctx, fake_runner):
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(NTFS3G, Answer.timeout())
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED)

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET, steps=(NTFS3G_RW,))

    assert result.outcomes == (StepOutcome(NTFS3G_RW, "timeout", "timed out"),)
    assert (result.state, result.reason) == (VolumeState.MOUNT_FAILED, "unknown")


def test_tool_not_found_is_a_step_outcome(ctx, fake_runner):
    fake_runner.on(MOUNT, Answer.missing())
    fake_runner.on(readback(PERSONAL_TARGET), NOT_MOUNTED)

    result = chain(ctx, PERSONAL, PERSONAL_TARGET, steps=(NTFS3_RO,))

    assert result.outcomes == (StepOutcome(NTFS3_RO, "refused", "not found"),)
    assert (result.state, result.reason) == (VolumeState.MOUNT_FAILED, "unknown")


def test_each_step_marks_the_kernel_log(ctx, fake_runner, fake_kmsg):
    """Kernel lines printed before a step's mark are not that step's reason."""
    fake_kmsg.queue(f"ntfs3(sdb5): {KERNEL_DIRTY}")
    fake_kmsg.mark()  # printed before the attempt: history, not evidence
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, refused(32), refused(32))
    fake_runner.on(NTFS3G, refused(21))
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, repeat=True)

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert result.reason == "mount exit status 32"


def test_kernel_lines_of_another_device_are_ignored(ctx, fake_runner, fake_kmsg):
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, refused(32), refused(32))
    fake_runner.on(NTFS3G, refused(21))
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, repeat=True)
    fake_kmsg.queue(*kernel_messages("dm-0"))

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert result.reason == "mount exit status 32"


# --- run_chain: reason order ---------------------------------------------------


def _script_failing_chain(fake_runner, fake_kmsg, *, probe, ntfs3g, mount, kernel):
    fake_runner.on(PROBE, probe)
    fake_runner.on(NTFS3G, ntfs3g)
    fake_runner.on(MOUNT, mount, mount)
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, repeat=True)
    if kernel:
        fake_kmsg.queue(f"ntfs3(sdb5): {KERNEL_DIRTY}")


UNSAFE_STDERR = load_fixture("ntfs3g-stderr-unsafe.txt")


@pytest.mark.parametrize(
    ("probe", "ntfs3g", "mount", "kernel", "expected"),
    [
        pytest.param(
            probe_answer(15),
            refused(14, UNSAFE_STDERR),
            refused(32, MOUNT_WRONG_FS),
            True,
            "dirty",
            id="probe-first",
        ),
        pytest.param(
            probe_answer(0),
            refused(14, UNSAFE_STDERR),
            refused(32, MOUNT_WRONG_FS),
            True,
            "unsafe",
            id="ntfs3g-text-before-kmsg",
        ),
        pytest.param(
            probe_answer(0),
            refused(15),
            refused(32, MOUNT_WRONG_FS),
            False,
            "dirty",
            id="ntfs3g-exit-15",
        ),
        pytest.param(
            probe_answer(0),
            refused(14),
            refused(32, MOUNT_WRONG_FS),
            False,
            "unsafe",
            id="ntfs3g-exit-14",
        ),
        pytest.param(
            probe_answer(0),
            refused(21),
            refused(32, MOUNT_WRONG_FS),
            True,
            "dirty",
            id="kmsg-before-mount-status",
        ),
        pytest.param(
            probe_answer(0),
            refused(21),
            refused(32, MOUNT_WRONG_FS),
            False,
            MOUNT_WRONG_FS_LINE,
            id="mount-status-message",
        ),
        pytest.param(
            probe_answer(0),
            refused(21),
            refused(32),
            False,
            "mount exit status 32",
            id="mount-status-code",
        ),
        pytest.param(
            probe_answer(0),
            Answer(),
            Answer(),
            False,
            "unknown",
            id="unknown",
        ),
    ],
)
def test_reason_order(
    ctx, fake_runner, fake_kmsg, probe, ntfs3g, mount, kernel, expected
):
    """ADR-0003 Decision 7: probe, ntfs-3g, kmsg, mount status, then unknown."""
    _script_failing_chain(
        fake_runner, fake_kmsg, probe=probe, ntfs3g=ntfs3g, mount=mount, kernel=kernel
    )

    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    assert result.state is VolumeState.MOUNT_FAILED
    assert result.reason == expected


# --- run_chain: non-NTFS -------------------------------------------------------


def test_exfat_is_one_rw_step_without_a_probe(ctx, fake_runner):
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback(GAMES_TARGET), GAMES_EXFAT_RW)

    result = chain(ctx, GAMES, GAMES_TARGET, fstype="exfat")

    assert (result.state, result.driver, result.reason) == (
        VolumeState.MOUNTED_RW,
        "exfat",
        "",
    )
    assert fake_runner.argvs[0] == kernel_argv(
        "exfat",
        "nosuid,nodev,uid=1000,gid=1000,umask=0022,iocharset=utf8,errors=remount-ro",
        "/dev/sdc1",
        GAMES_TARGET,
    )
    assert PROBE not in {argv[0] for argv in fake_runner.argvs}


def test_non_ntfs_refusal_reports_the_tool_message(ctx, fake_runner):
    message = b"mount: /run/media/deck/GAMES: can't read superblock on /dev/sdc1.\n"
    fake_runner.on(MOUNT, refused(32, message))
    fake_runner.on(readback(GAMES_TARGET), NOT_MOUNTED)

    result = chain(ctx, GAMES, GAMES_TARGET, fstype="exfat")

    assert result.state is VolumeState.MOUNT_FAILED
    assert result.reason == message.decode().strip()


def test_non_ntfs_with_a_drivers_list_is_a_programming_error(ctx):
    with pytest.raises(ValueError, match="drivers"):
        chain(ctx, GAMES, GAMES_TARGET, fstype="exfat", steps=(NTFS3G_RW,))


@pytest.mark.parametrize("fstype", ["ext4", "BitLocker", "fuseblk"])
def test_unsupported_fstype_is_a_programming_error(ctx, fstype):
    with pytest.raises(ValueError, match="fstype"):
        chain(ctx, GAMES, GAMES_TARGET, fstype=fstype)


def test_empty_chain_is_a_programming_error(ctx):
    with pytest.raises(ValueError, match="empty"):
        chain(ctx, MEDIABOX, MEDIABOX_TARGET, steps=())


def test_opt_out_reaches_the_argv(ctx, fake_runner):
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback(PERSONAL_TARGET), PERSONAL_NTFS3_RO)

    chain(ctx, PERSONAL, PERSONAL_TARGET, steps=(NTFS3_RO,), nosuid=False)

    assert (
        fake_runner.argvs[0][5] == "ro,nodev,uid=1000,gid=1000,umask=0022,windows_names"
    )


# --- run_chain: deadline and step timeouts -----------------------------------


def test_deadline_before_the_first_step_times_out(ctx, fake_runner, fake_clock):
    result = chain(ctx, MEDIABOX, MEDIABOX_TARGET, deadline=fake_clock.monotonic())

    assert (result.state, result.reason) == (VolumeState.MOUNT_TIMED_OUT, "deadline")
    assert fake_runner.argvs == []


def test_deadline_during_the_chain_stops_it(ctx, fake_runner, fake_clock):
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(
        MOUNT, Answer.timeout(), hook=lambda _cmd: fake_clock.advance(STEP_TIMEOUT)
    )
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED)

    result = chain(
        ctx, MEDIABOX, MEDIABOX_TARGET, deadline=fake_clock.monotonic() + 25.0
    )

    assert (result.state, result.reason) == (VolumeState.MOUNT_TIMED_OUT, "deadline")
    assert result.outcomes == (StepOutcome(NTFS3_RW, "timeout", "timed out"),)
    assert NTFS3G not in {argv[0] for argv in fake_runner.argvs}


def test_step_timeout_is_30_s_capped_by_the_deadline(ctx, fake_runner, fake_clock):
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, refused(32), Answer())
    fake_runner.on(NTFS3G, refused(21), hook=lambda _cmd: fake_clock.advance(50.0))
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, repeat=True)

    chain(ctx, MEDIABOX, MEDIABOX_TARGET, deadline=fake_clock.monotonic() + 60.0)

    timeouts = [
        call.timeout for call in fake_runner.calls if call.argv[0] in {MOUNT, NTFS3G}
    ]
    assert STEP_TIMEOUT == 30.0
    assert timeouts == [30.0, 30.0, 10.0]


def test_a_step_that_timed_out_but_mounted_counts(ctx, fake_runner):
    """findmnt decides, even after a timeout."""
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, Answer.timeout())
    fake_runner.on(readback(PERSONAL_TARGET), PERSONAL_NTFS3_RW)

    result = chain(ctx, PERSONAL, PERSONAL_TARGET)

    assert result.state is VolumeState.MOUNTED_RW
    assert result.outcomes == (StepOutcome(NTFS3_RW, "mounted", "timed out"),)


# --- flag conformance ----------------------------------------------------------

# ADR-0003 "Device Facts": ``ntfs-3g --help`` on the Deck lists ``ro``,
# ``windows_names``, ``uid=``, ``gid=``, ``umask=`` (no capture of the full help
# exists: tool-versions.txt kept only an empty first line). ``nosuid`` and
# ``nodev`` are generic mount options FUSE passes to the kernel.
NTFS3G_HELP_OPTIONS = frozenset({"ro", "windows_names", "uid", "gid", "umask"})
GENERIC_MOUNT_OPTIONS = frozenset({"nosuid", "nodev"})


def test_probe_flags_appear_in_the_probe_help(ctx, fake_runner):
    """Every flag the chain passes to ntfs-3g.probe is in its real ``--help``."""
    help_text = load_fixture("ntfs-3g.probe-help.txt").decode()
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, Answer())
    fake_runner.on(readback(PERSONAL_TARGET), PERSONAL_NTFS3_RW)

    chain(ctx, PERSONAL, PERSONAL_TARGET)

    probe_argv = next(argv for argv in fake_runner.argvs if argv[0] == PROBE)
    flags = [item for item in probe_argv[1:] if item.startswith("-")]
    assert flags == ["--readwrite"]
    assert all(flag in help_text for flag in flags)


def test_ntfs3g_flags_and_options_are_documented(ctx, fake_runner):
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, refused(32))
    fake_runner.on(NTFS3G, Answer())
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, MEDIABOX_FUSE_RW)

    chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    argv = next(argv for argv in fake_runner.argvs if argv[0] == NTFS3G)
    assert [item for item in argv[1:] if item.startswith("-")] == ["-o"]
    names = {option.split("=")[0] for option in argv[2].split(",")}
    assert names <= NTFS3G_HELP_OPTIONS | GENERIC_MOUNT_OPTIONS


def test_no_forbidden_option_in_any_chain_argv(ctx, fake_runner):
    fake_runner.on(PROBE, probe_answer(0))
    fake_runner.on(MOUNT, refused(32), refused(32))
    fake_runner.on(NTFS3G, refused(21))
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED, repeat=True)

    chain(ctx, MEDIABOX, MEDIABOX_TARGET)

    options = every_option_in(fake_runner.argvs)
    assert options
    assert not [option for option in options if option.split("=")[0] in FORBIDDEN]


# --- mount base (AC-024, IP-17) ----------------------------------------------


def mode_of(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@pytest.fixture
def run_dir(tmp_path) -> Path:
    """``/run`` exists on every boot; the tool creates nothing above /run/media."""
    path = tmp_path / "run"
    path.mkdir()
    return path


@pytest.mark.usefixtures("run_dir")
def test_mount_base_created_with_acl(ctx, fake_runner, tmp_path):
    fake_runner.on(SETFACL, Answer())

    ensure_mount_base(ctx)

    assert mode_of(tmp_path / "run/media") == 0o755
    assert mode_of(tmp_path / "run/media/deck") == 0o750
    assert fake_runner.argvs == [(SETFACL, "-m", "u:1000:r-x", "/run/media/deck")]


@pytest.mark.usefixtures("run_dir")
def test_mount_base_matches_udisks_layout(ctx, fake_runner, tmp_path):
    """The created layout equals what udisks made on the Deck (stat and getfacl)."""
    fake_runner.on(SETFACL, Answer())
    expected_modes = {}
    for line in load_fixture("stat-run-media.txt").decode().splitlines():
        path, owner, mode, kind = line.split(" ")
        assert (owner, kind) == ("root:root", "directory")
        expected_modes[path] = int(mode, 8)
    acl = load_fixture("getfacl-run-media-deck.txt").decode().splitlines()

    ensure_mount_base(ctx)

    created = {path: mode_of(ctx.paths.p(path)) for path in expected_modes}
    assert created == expected_modes
    _, _, entry, base = fake_runner.argvs[0]
    assert f"# file: {base}" in acl
    tag, uid, permissions = entry.split(":")
    assert f"{'user' if tag == 'u' else tag}:{uid}:{permissions}" in acl


def test_mount_base_left_alone_when_present(ctx, fake_runner, tmp_path):
    """Never changed when present: no setfacl, the mode stays as found."""
    base = tmp_path / "run/media/deck"
    base.mkdir(parents=True)
    base.chmod(0o700)

    ensure_mount_base(ctx)

    assert mode_of(base) == 0o700
    assert fake_runner.argvs == []


def test_mount_base_parent_present_only_base_created(ctx, fake_runner, tmp_path):
    parent = tmp_path / "run/media"
    parent.mkdir(parents=True)
    parent.chmod(0o711)
    fake_runner.on(SETFACL, Answer())

    ensure_mount_base(ctx)

    assert mode_of(parent) == 0o711
    assert mode_of(parent / "deck") == 0o750


@pytest.mark.usefixtures("run_dir")
def test_mount_base_setfacl_failure_removes_the_new_base(ctx, fake_runner, tmp_path):
    """IP-17: failure -> error; the next attempt recreates it with the ACL."""
    fake_runner.on(SETFACL, refused(1, b"setfacl: Operation not supported\n"))

    with pytest.raises(ToolError) as caught:
        ensure_mount_base(ctx)

    assert "Operation not supported" in caught.value.detail
    assert not (tmp_path / "run/media/deck").exists()


@pytest.mark.parametrize("make", ["file", "symlink"])
def test_mount_base_that_is_not_a_directory_is_refused(
    ctx, fake_runner, tmp_path, make
):
    base = tmp_path / "run/media/deck"
    base.parent.mkdir(parents=True)
    if make == "file":
        base.write_text("")
    else:
        (tmp_path / "elsewhere").mkdir()
        base.symlink_to(tmp_path / "elsewhere")

    with pytest.raises(MounterError, match="mount base"):
        ensure_mount_base(ctx)

    assert fake_runner.argvs == []


def test_mount_base_mkdir_failure_is_reported(ctx, fake_runner, tmp_path):
    (tmp_path / "run").write_text("")  # /run is a file: mkdir fails

    with pytest.raises(MounterError, match="mount base") as caught:
        ensure_mount_base(ctx)

    assert "/run/media" in caught.value.detail


# --- prepare_target (DD-26) --------------------------------------------------


@pytest.fixture
def base(tmp_path) -> Path:
    path = tmp_path / "run/media/deck"
    path.mkdir(parents=True)
    return path


def test_prepare_target_creates_only_the_leaf(ctx, base):
    created = prepare_target(ctx, MEDIABOX_TARGET)

    assert created is True
    assert mode_of(base / "MEDIABOX") == 0o755


def test_prepare_target_reuses_an_empty_directory(ctx, base):
    (base / "MEDIABOX").mkdir()

    assert prepare_target(ctx, MEDIABOX_TARGET) is False


def test_prepare_target_accepts_a_unicode_auto_name(ctx, base):
    assert prepare_target(ctx, "/run/media/deck/MÉDIA") is True
    assert (base / "MÉDIA").is_dir()


def test_prepare_target_refuses_a_fixed_path_outside_the_base(ctx, tmp_path, base):
    """Rule 9 (DD-34): only children of the mount base are mount targets."""
    (tmp_path / "home/deck/Drives").mkdir(parents=True)

    with pytest.raises(RefusedError, match=NOT_BASE_CHILD):
        prepare_target(ctx, "/home/deck/Drives/MEDIABOX")

    assert not (tmp_path / "home/deck/Drives/MEDIABOX").exists()


@pytest.mark.parametrize(
    ("setup", "target", "message"),
    [
        ("non_empty", MEDIABOX_TARGET, "not empty"),
        ("file", MEDIABOX_TARGET, "not a directory"),
        ("symlink", MEDIABOX_TARGET, "not a directory"),
        (None, "/home/deck/Drives/MEDIABOX", NOT_BASE_CHILD),
        (None, "/etc/MEDIABOX", NOT_BASE_CHILD),
        (None, "/run/media/deck/MEDIABOX/inner", NOT_BASE_CHILD),
        (None, "/run/media/deck/..", "not normalized"),
        (None, "/run/media/deck/.", "not normalized"),
        (None, "/run/media/deck/", "not normalized"),
        (None, "/run/media/deck//MEDIABOX", "not normalized"),
        ("file", MEDIABOX_TARGET + "/inner", NOT_BASE_CHILD),
        (None, "/run/media/deck/A\x07B", "control character"),
        (None, "/run/media/deck", NOT_BASE_CHILD),
        (None, "run/media/deck/MEDIABOX", NOT_BASE_CHILD),
    ],
)
def test_prepare_target_refusals(ctx, base, setup, target, message):
    leaf = base / "MEDIABOX"
    if setup == "non_empty":
        leaf.mkdir()
        (leaf / "file").write_text("")
    elif setup == "file":
        leaf.write_text("")
    elif setup == "symlink":
        leaf.symlink_to(base)

    with pytest.raises(RefusedError, match=message):
        prepare_target(ctx, target)


def test_prepare_target_symlinked_parent_is_refused(ctx, tmp_path, base):
    """DD-26: root never creates a directory through a link the owner controls."""
    (tmp_path / "home/deck").mkdir(parents=True)
    (tmp_path / "home/deck/Drives").symlink_to(
        tmp_path / "etc", target_is_directory=True
    )
    (tmp_path / "etc").mkdir()

    with pytest.raises(RefusedError, match=NOT_BASE_CHILD):
        prepare_target(ctx, "/home/deck/Drives/MEDIABOX")

    assert not (tmp_path / "etc/MEDIABOX").exists()


@pytest.mark.parametrize("base_is", ["missing", "symlink"])
def test_prepare_target_needs_a_real_mount_base(ctx, tmp_path, base_is):
    """An auto target is never created when the base is gone or was swapped."""
    media = tmp_path / "run/media"
    media.mkdir(parents=True)
    if base_is == "symlink":
        (tmp_path / "elsewhere").mkdir()
        (media / "deck").symlink_to(tmp_path / "elsewhere")

    with pytest.raises(RefusedError, match="parent directory does not exist"):
        prepare_target(ctx, MEDIABOX_TARGET)

    assert not (tmp_path / "elsewhere/MEDIABOX").exists()


def test_prepare_target_mkdir_failure_is_reported(ctx, base, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(mountdirs.os, "mkdir", refuse)

    with pytest.raises(MounterError, match="mount directory") as caught:
        prepare_target(ctx, MEDIABOX_TARGET)

    assert caught.value.detail == f"{MEDIABOX_TARGET}: Permission denied"


# --- unmount -------------------------------------------------------------------


def umount_argv(*flags: str) -> tuple[str, ...]:
    return (UMOUNT, *flags, MEDIABOX_TARGET)


def test_unmount_absent_target_runs_no_umount(ctx, fake_runner):
    fake_runner.on(readback(MEDIABOX_TARGET), NOT_MOUNTED)

    result = unmount(ctx, MEDIABOX_TARGET, mode="normal", timeout=20.0)

    assert result == UnmountResult(MEDIABOX_TARGET, "absent", "")
    assert fake_runner.argvs == [readback(MEDIABOX_TARGET)]


def test_unmount_normal(ctx, fake_runner):
    fake_runner.on(readback(MEDIABOX_TARGET), MEDIABOX_FUSE_RW)
    fake_runner.on(UMOUNT, Answer())

    result = unmount(ctx, MEDIABOX_TARGET, mode="normal", timeout=60.0)

    assert result.result == "unmounted"
    assert fake_runner.calls[-1].argv == umount_argv()
    assert fake_runner.calls[-1].timeout == NORMAL_UNMOUNT_TIMEOUT == 20.0


def test_unmount_normal_busy(ctx, fake_runner):
    """CLI ``unmount``: busy -> no lazy unmount for an owner command."""
    fake_runner.on(readback(MEDIABOX_TARGET), MEDIABOX_FUSE_RW)
    fake_runner.on(UMOUNT, refused(32, UMOUNT_BUSY))

    result = unmount(ctx, MEDIABOX_TARGET, mode="normal", timeout=20.0)

    assert result == UnmountResult(
        MEDIABOX_TARGET, "busy", "umount: /run/media/deck/MEDIABOX: target is busy."
    )
    assert [argv for argv in fake_runner.argvs if argv[0] == UMOUNT] == [umount_argv()]


def test_unmount_normal_other_failure(ctx, fake_runner):
    fake_runner.on(readback(MEDIABOX_TARGET), MEDIABOX_FUSE_RW)
    fake_runner.on(UMOUNT, refused(32, b"umount: permission denied\n"))

    result = unmount(ctx, MEDIABOX_TARGET, mode="normal-then-lazy", timeout=20.0)

    assert result == UnmountResult(
        MEDIABOX_TARGET, "failed", "umount: permission denied"
    )
    assert len([argv for argv in fake_runner.argvs if argv[0] == UMOUNT]) == 1


def test_unmount_lazy(ctx, fake_runner):
    """Unplug: ``umount -l`` each recorded target, 10 s."""
    fake_runner.on(readback(MEDIABOX_TARGET), MEDIABOX_FUSE_RW)
    fake_runner.on(UMOUNT, Answer())

    result = unmount(ctx, MEDIABOX_TARGET, mode="lazy", timeout=60.0)

    assert result.result == "lazy"
    assert fake_runner.calls[-1].argv == umount_argv("-l")
    assert fake_runner.calls[-1].timeout == LAZY_UNMOUNT_TIMEOUT == 10.0


@pytest.mark.parametrize("normal", [refused(32, UMOUNT_BUSY), Answer.timeout()])
def test_unmount_normal_then_lazy_falls_back_when_busy(ctx, fake_runner, normal):
    """Deliberate stop: normal first so ntfs-3g can flush; busy -> lazy, reported."""
    fake_runner.on(readback(MEDIABOX_TARGET), MEDIABOX_FUSE_RW)
    fake_runner.on(UMOUNT, normal, Answer())

    result = unmount(ctx, MEDIABOX_TARGET, mode="normal-then-lazy", timeout=60.0)

    assert result.result == "lazy"
    assert [argv for argv in fake_runner.argvs if argv[0] == UMOUNT] == [
        umount_argv(),
        umount_argv("-l"),
    ]


def test_unmount_normal_then_lazy_without_busy_is_unmounted(ctx, fake_runner):
    fake_runner.on(readback(MEDIABOX_TARGET), MEDIABOX_FUSE_RW)
    fake_runner.on(UMOUNT, Answer())

    result = unmount(ctx, MEDIABOX_TARGET, mode="normal-then-lazy", timeout=60.0)

    assert result.result == "unmounted"


def test_unmount_lazy_failure(ctx, fake_runner):
    fake_runner.on(readback(MEDIABOX_TARGET), MEDIABOX_FUSE_RW)
    fake_runner.on(UMOUNT, refused(32, UMOUNT_BUSY), Answer.missing())

    result = unmount(ctx, MEDIABOX_TARGET, mode="normal-then-lazy", timeout=60.0)

    assert result == UnmountResult(MEDIABOX_TARGET, "failed", "not found")


def test_unmount_timeout_caps_each_call(ctx, fake_runner):
    fake_runner.on(readback(MEDIABOX_TARGET), MEDIABOX_FUSE_RW)
    fake_runner.on(UMOUNT, refused(32, UMOUNT_BUSY), Answer())

    unmount(ctx, MEDIABOX_TARGET, mode="normal-then-lazy", timeout=5.0)

    assert [call.timeout for call in fake_runner.calls if call.argv[0] == UMOUNT] == [
        5.0,
        5.0,
    ]


def test_unmount_refuses_a_relative_target(ctx):
    with pytest.raises(ValueError, match="absolute"):
        unmount(ctx, "run/media/deck/MEDIABOX", mode="normal", timeout=20.0)


@pytest.mark.parametrize("module", [mounter, mountdirs])
def test_module_stays_under_500_lines(module):
    assert len(Path(module.__file__).read_text().splitlines()) < 500


def test_mounter_reexports_the_mount_directory_functions():
    """The Design Doc names ``mounter.ensure_mount_base`` and ``prepare_target``."""
    assert mounter.ensure_mount_base is mountdirs.ensure_mount_base
    assert mounter.prepare_target is mountdirs.prepare_target
