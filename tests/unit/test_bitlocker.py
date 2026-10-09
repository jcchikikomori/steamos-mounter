"""BitLocker unlock, close and mapping discovery.

Design Doc "BitLocker Unlock and Mappings" (the argv table and exit codes),
"Module Responsibilities > bitlocker", DD-15 (own mappings by tool name,
foreign ones by device number only), DD-29 (poll lsblk for the inner type for
at most 5 s), IP-10 and IP-11.

- Every argv is pinned byte for byte, and every flag in it is checked against
  the Deck's ``cryptsetup --help`` and ``dmsetup --help`` captures.
- sysfs is real files under ``tmp_path`` from ``sysfs-facts.txt`` (``dm-0`` is
  Dolphin's mapping on ``sdb1``) plus a tool mapping ``dm-1`` where needed.
- The 5 s poll runs on ``FakeClock``: ``time.sleep`` is replaced with the
  clock's ``advance`` so no test waits.

Key bytes are compared as booleans computed before the assertion, so a
failing test never prints them.
"""

import json
import re

import pytest

from steamos_mounter import bitlocker
from steamos_mounter.bitlocker import (
    MAPPING_PREFIX,
    UnlockOutcome,
    close_own,
    is_tool_mapping,
    mapping_name,
    mapping_on_container,
    mappings_stacked_on,
    open_with_file,
    open_with_secret,
    remove_by_devnum,
    wait_inner_ready,
)
from steamos_mounter.errors import InvalidKernelName, ToolError
from steamos_mounter.sensitive import SecretBytes
from tests.helpers.clock import DEFAULT_MONOTONIC
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture
from tests.helpers.host_tree import SysfsDevice

CRYPTSETUP = "/usr/bin/cryptsetup"
DMSETUP = "/usr/bin/dmsetup"
LSBLK = "/usr/bin/lsblk"
UUID = "658207d5-5177-4a52-a297-31643c64724d"
TOOL_NAME = "steamos-mounter-658207d5-5177-4a52-a297-31643c64724d"
DOLPHIN_NAME = "PAT4T4SHUAWEI_PERSONAL_4_3_2024"
DEVICE = "/dev/sdb1"
KEY_FILE = f"/var/lib/steamos-mounter/keys/{UUID}.key"
KEY = b"unit-test-key-bytes"
OPEN_TIMEOUT = 30.0
CLOSE_TIMEOUT = 10.0
DMSETUP_TIMEOUT = 10.0

TEST_ARGV = (
    CRYPTSETUP,
    "open",
    "--test-passphrase",
    "--type",
    "bitlk",
    "--key-file=-",
    DEVICE,
)
OPEN_SECRET_ARGV = (
    CRYPTSETUP,
    "open",
    "--type",
    "bitlk",
    "--key-file=-",
    DEVICE,
    TOOL_NAME,
)
OPEN_FILE_ARGV = (
    CRYPTSETUP,
    "open",
    "--type",
    "bitlk",
    "--key-file",
    KEY_FILE,
    DEVICE,
    TOOL_NAME,
)
CLOSE_ARGV = (CRYPTSETUP, "close", TOOL_NAME)
CLOSE_DEFERRED_ARGV = (CRYPTSETUP, "close", "--deferred", TOOL_NAME)
REMOVE_ARGV = (DMSETUP, "remove", "--deferred", "-j", "252", "-m", "0")
DEPS_DM0_ARGV = (DMSETUP, "deps", "-o", "devno", "-j", "252", "-m", "0")
DEPS_DM1_ARGV = (DMSETUP, "deps", "-o", "devno", "-j", "252", "-m", "1")
DEPS_FIXTURE = "dmsetup-deps-devno.txt"
# Synthetic fixtures have no capture-index row, so their exit status is given.
DEPS = Answer.from_fixture(DEPS_FIXTURE, returncode=0)

TREE_FIXTURE = "lsblk-columns-tree.json"
LOCKED_TREE_FIXTURE = "lsblk-tree-personal-locked.json"
LOCKED_TREE = Answer.from_fixture(LOCKED_TREE_FIXTURE, returncode=0)
READ_TREE_ARGV = (
    LSBLK,
    "--json",
    "--bytes",
    "--tree",
    "-o",
    "NAME,KNAME,PATH,MAJ:MIN,TYPE,FSTYPE,FSVER,LABEL,UUID,PTUUID,PTTYPE,PARTUUID,"
    "PARTLABEL,PARTTYPENAME,PKNAME,HOTPLUG,RM,RO,TRAN,SIZE,MOUNTPOINTS",
)
POLL_INTERVAL = 0.25

TOOL_MAPPING = SysfsDevice(
    kname="dm-1",
    devnum="252:1",
    dm_name=TOOL_NAME,
    slaves=("sdc1",),
)

UnlockCall = tuple[str, object]


@pytest.fixture
def key():
    secret = SecretBytes(KEY)
    yield secret
    secret.clear()


@pytest.fixture
def sysfs(host_tree):
    """The Deck's sysfs facts: ``dm-0`` (Dolphin's) on ``sdb1``."""
    host_tree.add_sysfs_facts()
    return host_tree


@pytest.fixture
def fake_sleep(monkeypatch, fake_clock):
    """``time.sleep`` advances the fake clock; returns the requested pauses."""
    pauses: list[float] = []

    def sleep(seconds: float) -> None:
        pauses.append(seconds)
        fake_clock.advance(seconds)

    monkeypatch.setattr(bitlocker.time, "sleep", sleep)
    return pauses


def tree_with_dm0_fstype(fstype: str | None) -> bytes:
    """The real tree with ``dm-0``'s inner type replaced (null = udev not done)."""
    document = json.loads(load_fixture(TREE_FIXTURE))
    sdb = next(item for item in document["blockdevices"] if item["kname"] == "sdb")
    sdb1 = next(item for item in sdb["children"] if item["kname"] == "sdb1")
    sdb1["children"][0]["fstype"] = fstype
    return json.dumps(document).encode()


def unlock(operation: str, ctx, key: SecretBytes) -> UnlockOutcome:
    if operation == "test_key":
        return bitlocker.test_key(ctx, DEVICE, key)
    if operation == "open_with_secret":
        return open_with_secret(ctx, DEVICE, UUID, key)
    return open_with_file(ctx, DEVICE, UUID, KEY_FILE)


UNLOCK_ARGVS = {
    "test_key": TEST_ARGV,
    "open_with_secret": OPEN_SECRET_ARGV,
    "open_with_file": OPEN_FILE_ARGV,
}


# --- mapping names --------------------------------------------------------------


def test_mapping_name_is_the_prefix_and_the_registry_uuid():
    assert mapping_name(UUID) == TOOL_NAME
    assert MAPPING_PREFIX == "steamos-mounter-"


@pytest.mark.parametrize("uuid", ["01D95F1575592A30", "C40C-B21F"])
def test_mapping_name_takes_every_registry_uuid_form(uuid):
    assert mapping_name(uuid) == f"steamos-mounter-{uuid}"


@pytest.mark.parametrize(
    "uuid", ["", "PERSONAL", "../658207d5", f"{UUID} x", f"-{UUID}", "--deferred"]
)
def test_mapping_name_refuses_anything_but_a_uuid(uuid):
    with pytest.raises(ValueError, match="not a registry UUID"):
        mapping_name(uuid)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (TOOL_NAME, True),
        ("steamos-mounter-anything", True),
        (DOLPHIN_NAME, False),
        ("steamos-mounter", False),
        ("x-steamos-mounter-658207d5", False),
        ("", False),
        (None, False),
    ],
)
def test_is_tool_mapping_checks_the_prefix(name, expected):
    assert is_tool_mapping(name) is expected


def test_unlock_outcome_values():
    assert [outcome.value for outcome in UnlockOutcome] == [
        "opened",
        "rejected",
        "failed",
    ]


# --- open and test argv ---------------------------------------------------------


def test_test_key_argv_and_key_on_stdin(ctx, fake_runner, key):
    fake_runner.on(CRYPTSETUP, Answer())

    outcome = bitlocker.test_key(ctx, DEVICE, key)

    call = fake_runner.calls[0]
    key_on_stdin = call.stdin == KEY
    assert outcome is UnlockOutcome.OPENED
    assert call.argv == TEST_ARGV
    assert call.secret_stdin
    assert key_on_stdin
    assert call.timeout == OPEN_TIMEOUT
    assert call.env_extra == {}


def test_open_with_secret_argv_and_key_on_stdin(ctx, fake_runner, key):
    fake_runner.on(CRYPTSETUP, Answer())

    outcome = open_with_secret(ctx, DEVICE, UUID, key)

    call = fake_runner.calls[0]
    key_on_stdin = call.stdin == KEY
    assert outcome is UnlockOutcome.OPENED
    assert call.argv == OPEN_SECRET_ARGV
    assert call.secret_stdin
    assert key_on_stdin
    assert call.timeout == OPEN_TIMEOUT


def test_open_with_file_passes_only_the_path(ctx, fake_runner):
    fake_runner.on(CRYPTSETUP, Answer())

    outcome = open_with_file(ctx, DEVICE, UUID, KEY_FILE)

    call = fake_runner.calls[0]
    assert outcome is UnlockOutcome.OPENED
    assert call.argv == OPEN_FILE_ARGV
    assert not call.has_stdin
    assert call.timeout == OPEN_TIMEOUT


def test_unlock_leaves_the_callers_secret_live(ctx, fake_runner, key):
    fake_runner.on(CRYPTSETUP, Answer(), repeat=True)

    bitlocker.test_key(ctx, DEVICE, key)
    open_with_secret(ctx, DEVICE, UUID, key)

    still_usable = key.reveal() == KEY
    assert still_usable


@pytest.mark.parametrize("operation", sorted(UNLOCK_ARGVS))
@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (Answer(returncode=0), UnlockOutcome.OPENED),
        (Answer(returncode=2, stderr=b"No key available"), UnlockOutcome.REJECTED),
        (Answer(returncode=1), UnlockOutcome.FAILED),
        (Answer(returncode=4), UnlockOutcome.FAILED),
        (Answer(returncode=5, stderr=b"Device already exists"), UnlockOutcome.FAILED),
        (Answer.timeout(), UnlockOutcome.FAILED),
        (Answer.missing(), UnlockOutcome.FAILED),
    ],
)
def test_unlock_exit_codes(ctx, fake_runner, key, operation, answer, expected):
    fake_runner.on(CRYPTSETUP, answer)

    outcome = unlock(operation, ctx, key)

    assert outcome is expected
    assert fake_runner.argvs == [UNLOCK_ARGVS[operation]]


def test_unlock_failure_is_logged_with_the_tool_detail(ctx, fake_runner, key, caplog):
    fake_runner.on(CRYPTSETUP, Answer(returncode=1, stderr=b"Cannot read header"))

    with caplog.at_level("ERROR", logger="steamos_mounter.bitlocker"):
        open_with_secret(ctx, DEVICE, UUID, key)

    assert caplog.messages == [
        f"cryptsetup open {TOOL_NAME} failed: exit 1, timed out False, "
        "not found False: Cannot read header"
    ]


@pytest.mark.parametrize("device", ["sdb1", "dev/sdb1", "", "--key-file=/x"])
@pytest.mark.parametrize("operation", sorted(UNLOCK_ARGVS))
def test_unlock_refuses_a_device_that_is_not_absolute(
    ctx, fake_runner, key, device, operation
):
    calls = {
        "test_key": lambda: bitlocker.test_key(ctx, device, key),
        "open_with_secret": lambda: open_with_secret(ctx, device, UUID, key),
        "open_with_file": lambda: open_with_file(ctx, device, UUID, KEY_FILE),
    }

    with pytest.raises(ValueError, match="must be an absolute path"):
        calls[operation]()

    assert fake_runner.calls == []


@pytest.mark.parametrize("path", ["key", "keys/x.key", "", "-"])
def test_open_with_file_refuses_a_key_path_that_is_not_absolute(ctx, fake_runner, path):
    with pytest.raises(ValueError, match="must be an absolute path"):
        open_with_file(ctx, DEVICE, UUID, path)

    assert fake_runner.calls == []


@pytest.mark.parametrize("operation", ["open_with_secret", "open_with_file"])
def test_open_refuses_a_uuid_before_running_anything(ctx, fake_runner, key, operation):
    with pytest.raises(ValueError, match="not a registry UUID"):
        if operation == "open_with_secret":
            open_with_secret(ctx, DEVICE, "PERSONAL", key)
        else:
            open_with_file(ctx, DEVICE, "PERSONAL", KEY_FILE)

    assert fake_runner.calls == []


# --- close own ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("deferred", "argv"), [(False, CLOSE_ARGV), (True, CLOSE_DEFERRED_ARGV)]
)
def test_close_own_argv(ctx, fake_runner, sysfs, deferred, argv):
    sysfs.add_block(TOOL_MAPPING)
    fake_runner.on(CRYPTSETUP, Answer())

    result = close_own(ctx, UUID, deferred=deferred)

    assert result == "closed"
    assert fake_runner.argvs == [argv]
    assert fake_runner.calls[0].timeout == CLOSE_TIMEOUT
    assert not fake_runner.calls[0].has_stdin


def test_close_own_exit_5_is_busy(ctx, fake_runner, sysfs):
    sysfs.add_block(TOOL_MAPPING)
    fake_runner.on(CRYPTSETUP, Answer(returncode=5, stderr=b"Device is still in use"))

    assert close_own(ctx, UUID, deferred=False) == "busy"


def test_close_own_without_the_mapping_is_absent_and_runs_nothing(
    ctx, fake_runner, sysfs
):
    # dm-0 is Dolphin's mapping; the tool's name is nowhere in sysfs.
    assert close_own(ctx, UUID, deferred=True) == "absent"
    assert fake_runner.calls == []


def test_close_own_without_any_dm_device_is_absent(ctx, fake_runner):
    assert close_own(ctx, UUID, deferred=False) == "absent"
    assert fake_runner.calls == []


def test_close_own_mapping_gone_during_the_call_is_absent(
    ctx, fake_runner, sysfs, tmp_path
):
    sysfs.add_block(TOOL_MAPPING)

    def vanish(_cmd):
        (tmp_path / "sys/block/dm-1").unlink()

    fake_runner.on(CRYPTSETUP, Answer(returncode=4), hook=vanish)

    assert close_own(ctx, UUID, deferred=False) == "absent"


@pytest.mark.parametrize(
    "answer", [Answer(returncode=4), Answer(returncode=1), Answer.timeout()]
)
def test_close_own_other_failure_with_the_mapping_still_there_is_failed(
    ctx, fake_runner, sysfs, answer, caplog
):
    sysfs.add_block(TOOL_MAPPING)
    fake_runner.on(CRYPTSETUP, answer)

    with caplog.at_level("ERROR", logger="steamos_mounter.bitlocker"):
        result = close_own(ctx, UUID, deferred=True)

    assert result == "failed"
    assert caplog.messages[0].startswith(f"cryptsetup close {TOOL_NAME} failed: ")


def test_close_own_refuses_a_non_uuid(ctx, fake_runner, sysfs):
    with pytest.raises(ValueError, match="not a registry UUID"):
        close_own(ctx, DOLPHIN_NAME, deferred=False)

    assert fake_runner.calls == []


# --- remove foreign by device number (DD-15) ------------------------------------


def test_remove_by_devnum_argv(ctx, fake_runner):
    fake_runner.on(DMSETUP, Answer())

    result = remove_by_devnum(ctx, "252:0")

    assert result == "removed"
    assert fake_runner.argvs == [REMOVE_ARGV]
    assert fake_runner.calls[0].timeout == DMSETUP_TIMEOUT


@pytest.mark.parametrize(
    "answer", [Answer(returncode=1), Answer.timeout(), Answer.missing()]
)
def test_remove_by_devnum_failure(ctx, fake_runner, answer, caplog):
    fake_runner.on(DMSETUP, answer)

    with caplog.at_level("ERROR", logger="steamos_mounter.bitlocker"):
        result = remove_by_devnum(ctx, "252:0")

    assert result == "failed"
    assert caplog.messages[0].startswith("dmsetup remove 252:0 failed: ")


@pytest.mark.parametrize(
    "devnum", ["252", "252:", ":0", "a:b", "252:0 ", "252:0:1", DOLPHIN_NAME, ""]
)
def test_remove_by_devnum_refuses_anything_but_a_device_number(
    ctx, fake_runner, devnum
):
    with pytest.raises(ValueError, match="not a device number"):
        remove_by_devnum(ctx, devnum)

    assert fake_runner.calls == []


# --- stacked mappings (teardown at unplug) --------------------------------------


def test_mappings_stacked_on_finds_dolphins_mapping_by_devnum(ctx, fake_runner, sysfs):
    sysfs.add_block(TOOL_MAPPING)
    fake_runner.on(DEPS_DM0_ARGV, DEPS)
    fake_runner.on(DEPS_DM1_ARGV, Answer(stdout=b"1 dependencies\t: (8, 33)\n"))

    found = mappings_stacked_on(ctx, ["8:17"])

    assert found == (("252:0", DOLPHIN_NAME),)
    assert fake_runner.argvs == [DEPS_DM0_ARGV, DEPS_DM1_ARGV]
    assert {call.timeout for call in fake_runner.calls} == {DMSETUP_TIMEOUT}


def test_mappings_stacked_on_returns_own_and_foreign_in_dm_order(
    ctx, fake_runner, sysfs
):
    sysfs.add_block(TOOL_MAPPING)
    fake_runner.on(DEPS_DM0_ARGV, DEPS)
    fake_runner.on(DEPS_DM1_ARGV, Answer(stdout=b"1 dependencies\t: (8, 33)\n"))

    found = mappings_stacked_on(ctx, iter(["8:33", "8:17"]))

    assert found == (("252:0", DOLPHIN_NAME), ("252:1", TOOL_NAME))


def test_mappings_stacked_on_orders_dm_devices_numerically(ctx, fake_runner, host_tree):
    for number in (10, 2):
        host_tree.add_block(
            SysfsDevice(kname=f"dm-{number}", devnum=f"252:{number}", dm_name="x")
        )
    fake_runner.on(DMSETUP, Answer(stdout=b"1 dependencies\t: (8, 17)\n"), repeat=True)

    found = mappings_stacked_on(ctx, ["8:17"])

    assert found == (("252:2", "x"), ("252:10", "x"))


def test_mappings_stacked_on_reads_every_dependency(ctx, fake_runner, sysfs):
    fake_runner.on(DEPS_DM0_ARGV, Answer(stdout=b"2 dependencies\t: (8, 17) (8, 18)\n"))

    assert mappings_stacked_on(ctx, ["8:18"]) == (("252:0", DOLPHIN_NAME),)


def test_mappings_stacked_on_without_a_name_gives_none(ctx, fake_runner, host_tree):
    host_tree.add_block(SysfsDevice(kname="dm-3", devnum="252:3"))
    fake_runner.on(DMSETUP, DEPS)

    assert mappings_stacked_on(ctx, ["8:17"]) == (("252:3", None),)


def test_mappings_stacked_on_nothing_asked_runs_nothing(ctx, fake_runner, sysfs):
    assert mappings_stacked_on(ctx, []) == ()
    assert fake_runner.calls == []


def test_mappings_stacked_on_without_sys_block_is_empty(ctx, fake_runner):
    assert mappings_stacked_on(ctx, ["8:17"]) == ()
    assert fake_runner.calls == []


def test_mappings_stacked_on_skips_non_dm_entries(ctx, fake_runner, host_tree):
    host_tree.add_block(SysfsDevice(kname="sdb", devnum="8:16"))
    host_tree.add_block(SysfsDevice(kname="loop0", devnum="7:0"))
    host_tree.path("/sys/block/dm-x").mkdir(parents=True)

    assert mappings_stacked_on(ctx, ["8:17"]) == ()
    assert fake_runner.calls == []


def test_mappings_stacked_on_skips_a_dm_without_dev(ctx, fake_runner, host_tree):
    host_tree.add_block(SysfsDevice(kname="dm-4", dm_name="gone"))

    assert mappings_stacked_on(ctx, ["8:17"]) == ()
    assert fake_runner.calls == []


@pytest.mark.parametrize(
    "answer",
    [
        Answer(returncode=1, stderr=b"Device does not exist."),
        Answer.timeout(),
        Answer(stdout=b"garbage\n"),
        Answer(stdout=b"2 dependencies\t: (8, 17)\n"),
        Answer(stdout=b""),
    ],
)
def test_mappings_stacked_on_skips_a_dm_dmsetup_cannot_describe(
    ctx, fake_runner, sysfs, answer, caplog
):
    sysfs.add_block(TOOL_MAPPING)
    fake_runner.on(DEPS_DM0_ARGV, answer)
    fake_runner.on(DEPS_DM1_ARGV, Answer(stdout=b"1 dependencies\t: (8, 17)\n"))

    with caplog.at_level("WARNING", logger="steamos_mounter.bitlocker"):
        found = mappings_stacked_on(ctx, ["8:17"])

    assert found == (("252:1", TOOL_NAME),)
    assert caplog.messages[0].startswith("dmsetup deps 252:0: ")


def test_mappings_stacked_on_with_no_dependencies(ctx, fake_runner, sysfs):
    fake_runner.on(DEPS_DM0_ARGV, Answer(stdout=b"0 dependencies\t:\n"))

    assert mappings_stacked_on(ctx, ["8:17"]) == ()


# --- mapping on a present container ---------------------------------------------


def test_mapping_on_container_reads_holders_and_dm_name(ctx, fake_runner, sysfs):
    assert mapping_on_container(ctx, "sdb1") == ("dm-0", DOLPHIN_NAME)
    assert fake_runner.calls == []


def test_mapping_on_container_without_holders_is_none(ctx, sysfs):
    assert mapping_on_container(ctx, "sdb5") is None


def test_mapping_on_container_absent_device_is_none(ctx, sysfs):
    assert mapping_on_container(ctx, "sdz9") is None


def test_mapping_on_container_ignores_holders_that_are_not_dm(ctx, host_tree):
    host_tree.add_block(SysfsDevice(kname="md0", devnum="9:0", slaves=("sdc1",)))
    host_tree.add_block(
        SysfsDevice(kname="sdc1", devnum="8:33", parent="sdc", holders=("md0",))
    )

    assert mapping_on_container(ctx, "sdc1") is None


def test_mapping_on_container_with_a_tool_mapping(ctx, host_tree):
    host_tree.add_block(TOOL_MAPPING)
    host_tree.add_block(
        SysfsDevice(kname="sdc1", devnum="8:33", parent="sdc", holders=("dm-1",))
    )

    assert mapping_on_container(ctx, "sdc1") == ("dm-1", TOOL_NAME)


def test_mapping_on_container_validates_the_kname(ctx, fake_runner):
    with pytest.raises(InvalidKernelName):
        mapping_on_container(ctx, "../sdb1")


# --- waiting for the inner filesystem (DD-29) -----------------------------------


def test_wait_inner_ready_returns_at_once_when_the_type_is_known(
    ctx, fake_runner, fake_sleep
):
    fake_runner.on(LSBLK, TREE_FIXTURE)

    device = wait_inner_ready(ctx, "dm-0")

    assert device is not None
    assert (device.kname, device.fstype, device.uuid) == (
        "dm-0",
        "ntfs",
        "88D48067D48058F8",
    )
    assert fake_runner.argvs == [READ_TREE_ARGV]
    assert fake_sleep == []


def test_wait_inner_ready_polls_until_the_type_appears(
    ctx, fake_runner, fake_clock, fake_sleep
):
    fake_runner.on(
        LSBLK,
        LOCKED_TREE,
        Answer(stdout=tree_with_dm0_fstype(None)),
        Answer(stdout=tree_with_dm0_fstype("ntfs")),
    )

    device = wait_inner_ready(ctx, "dm-0")

    assert device is not None
    assert device.fstype == "ntfs"
    assert len(fake_runner.calls) == 3
    assert fake_sleep == [POLL_INTERVAL, POLL_INTERVAL]
    assert fake_clock.monotonic() == DEFAULT_MONOTONIC + 0.5


def test_wait_inner_ready_gives_up_after_5_seconds(
    ctx, fake_runner, fake_clock, fake_sleep, caplog
):
    fake_runner.on(LSBLK, LOCKED_TREE, repeat=True)

    with caplog.at_level("WARNING", logger="steamos_mounter.bitlocker"):
        device = wait_inner_ready(ctx, "dm-0")

    assert device is None
    # Polls at 0, 0.25, ..., 5.0 s: 21 lsblk calls and never past the deadline.
    assert len(fake_runner.calls) == 21
    assert fake_clock.monotonic() == DEFAULT_MONOTONIC + 5.0
    assert max(fake_sleep) <= POLL_INTERVAL
    assert caplog.messages == ["dm-0: no inner filesystem type after 5.0 s"]


def test_wait_inner_ready_honours_a_shorter_timeout(
    ctx, fake_runner, fake_clock, fake_sleep
):
    fake_runner.on(LSBLK, Answer(stdout=tree_with_dm0_fstype(None)), repeat=True)

    assert wait_inner_ready(ctx, "dm-0", timeout=0.6) is None
    assert len(fake_runner.calls) == 4
    assert fake_sleep == [0.25, 0.25, pytest.approx(0.1)]
    assert fake_clock.monotonic() == pytest.approx(DEFAULT_MONOTONIC + 0.6)


def test_wait_inner_ready_lsblk_failure_propagates(ctx, fake_runner, fake_sleep):
    fake_runner.on(LSBLK, Answer(returncode=1, stderr=b"lsblk: failed"))

    with pytest.raises(ToolError):
        wait_inner_ready(ctx, "dm-0")


def test_wait_inner_ready_validates_the_kname(ctx, fake_runner):
    with pytest.raises(InvalidKernelName):
        wait_inner_ready(ctx, "dm-0/../sda")

    assert fake_runner.calls == []


# --- flag conformance against the Deck's help captures --------------------------


def every_argv(ctx, fake_runner, sysfs, key) -> list[tuple[str, ...]]:
    sysfs.add_block(TOOL_MAPPING)
    fake_runner.on(CRYPTSETUP, Answer(), repeat=True)
    fake_runner.on(DMSETUP, Answer(stdout=b"1 dependencies\t: (8, 17)\n"), repeat=True)
    bitlocker.test_key(ctx, DEVICE, key)
    open_with_secret(ctx, DEVICE, UUID, key)
    open_with_file(ctx, DEVICE, UUID, KEY_FILE)
    close_own(ctx, UUID, deferred=False)
    close_own(ctx, UUID, deferred=True)
    remove_by_devnum(ctx, "252:0")
    mappings_stacked_on(ctx, ["8:17"])
    return fake_runner.argvs


def help_has_option(help_text: str, option: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(option)}(?![\w-])", help_text) is not None


@pytest.mark.parametrize(
    ("tool", "help_fixture", "actions"),
    [
        (CRYPTSETUP, "cryptsetup-help.txt", {"open", "close"}),
        (DMSETUP, "dmsetup-help.txt", {"remove", "deps"}),
    ],
)
def test_every_flag_appears_in_the_captured_help(
    ctx, fake_runner, sysfs, key, tool, help_fixture, actions
):
    help_text = load_fixture(help_fixture).decode()

    argvs = [
        argv for argv in every_argv(ctx, fake_runner, sysfs, key) if argv[0] == tool
    ]

    options = {item.split("=")[0] for argv in argvs for item in argv if item[0] == "-"}
    used_actions = {argv[1] for argv in argvs}
    missing = sorted(item for item in options if not help_has_option(help_text, item))
    assert options
    assert missing == []
    assert used_actions == actions
    assert all(
        re.search(rf"^\s*{action} ", help_text, re.MULTILINE) for action in actions
    )


def test_bitlk_type_and_devno_output_are_in_the_captured_help():
    cryptsetup_help = load_fixture("cryptsetup-help.txt").decode()
    dmsetup_help = load_fixture("dmsetup-help.txt").decode()

    assert "bitlk" in cryptsetup_help
    assert "Options are: devno" in dmsetup_help


def test_help_flag_check_catches_an_unknown_flag():
    # Negative control for the conformance test above.
    help_text = load_fixture("cryptsetup-help.txt").decode()

    assert help_has_option(help_text, "--test-passphrase")
    assert not help_has_option(help_text, "--key")
    assert not help_has_option(help_text, "--passphrase")


def test_synthetic_deps_fixture_shape():
    text = load_fixture(DEPS_FIXTURE).decode()

    assert text == "1 dependencies\t: (8, 17)\n"
