"""Registered BitLocker with a stored key (PERSONAL) - integration skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "BitLocker with
Stored Key (PERSONAL)", "BitLocker Unlock and Mappings", "Key Store",
"UNLOCK_REGISTERED executor", DD-18, DD-29). Generated 2026-10-08 by the
acceptance-test-generator. Budget used: 2/3 integration for the feature
"BitLocker auto-unlock" (FR-03).

Test boundary: FakeRunner for lsblk, findmnt, cryptsetup, probe, mount, loginctl,
systemctl, systemd-run; real key file, registry, records and locks under
HostPaths(root=tmp_path) with trusted_uid = the test uid (so the 0700/0600
owner and mode checks of keystore.status run against real files).

The real tree fixtures/deck/lsblk-columns-tree.json already shows dm-0 (the
capture was taken after a Dolphin unlock). The stored-key flow therefore feeds
the FakeRunner two lsblk answers: first fixtures/synthetic/
lsblk-tree-personal-locked.json ("# synthetic: real tree minus dm-0"), then the
real tree once cryptsetup open has "created" dm-0. The host tree names dm-0
with the tool's mapping name so the dm-0 auto instance routes OWN_MAPPING.

Fixtures expected from tests/conftest.py: fake_runner, fake_platform, host_tree,
fake_kmsg, fake_clock, ctx. Skipped until steamos_mounter.reconcile exists.
"""

from pathlib import Path

import pytest

reconcile = pytest.importorskip("steamos_mounter.reconcile")
keystore = pytest.importorskip("steamos_mounter.keystore")
bitlocker = pytest.importorskip("steamos_mounter.bitlocker")

PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
PERSONAL_DEVICE_PATH = f"/dev/disk/by-uuid/{PERSONAL_UUID}"
PERSONAL_RECORD = f"run/steamos-mounter/records/registered/{PERSONAL_UUID}.json"
PERSONAL_INSTANCE = (
    "dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52\\x2da297\\x2d31643c64724d"
)
KEY_UNIT = f"steamos-mounter-key@{PERSONAL_INSTANCE}.service"
MAPPING_NAME = f"steamos-mounter-{PERSONAL_UUID}"
KEY_FILE = f"var/lib/steamos-mounter/keys/{PERSONAL_UUID}.key"
DM0_SYSPATH = "/sys/devices/virtual/block/dm-0"
DM0_RECORD = "run/steamos-mounter/records/auto/dm-0-252_0.json"
TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"


@pytest.fixture
def expected_open_argv() -> tuple[str, ...]:
    """cryptsetup open with the stored key file (Design Doc "BitLocker Unlock").

    The handler never reads the key into Python: the call carries the file
    path and no stdin.
    """
    return (
        "/usr/bin/cryptsetup",
        "open",
        "--type",
        "bitlk",
        "--key-file",
        f"/var/lib/steamos-mounter/keys/{PERSONAL_UUID}.key",
        "/dev/sdb1",
        MAPPING_NAME,
    )


# AC-010: "Given PERSONAL is registered with a valid key, when it is plugged in,
#   then it is unlocked and its inner filesystem is mounted at the fixed path
#   within the latency target, with no prompt."
# AC-059: "... its inner filesystem is mounted only at the registered fixed path.
#   The unregistered auto-mount path never mounts it."
# AC-011, AC-013 (key file layout; key never in argv, logs, records, registry)
# ROI: 99 (BV:10 x Freq:9 + Legal:0 + Defect:9)
# Behavior: container by-uuid unit plugged -> UNLOCK_REGISTERED -> key file ok ->
#   cryptsetup open --key-file -> wait_inner_ready sees dm-0 ntfs -> chain on
#   /dev/dm-0 at the fixed path -> MountedRW; dm-0 auto instance: OWN_MAPPING
# @category: core-functionality
# @dependency: reconcile, routing, keystore, bitlocker, blockdev, mounter, ntfs,
#   mounts, state, locks
# @complexity: high
# @real-dependency: tmp_path key file (0600, test uid), keys dir (0700), records,
#   sysfs slaves/holders/dm name, flock
def test_stored_key_unlocks_personal_and_mounts_inner_at_fixed_path(
    tmp_path: Path,
) -> None:
    """Design Doc "BitLocker with Stored Key (PERSONAL)" end to end.

    Given
      - HostPaths(root=tmp_path): registry with MEDIABOX and PERSONAL (see
        test_flow_registered_plugin.REGISTRY_TEXT), tmp_path/KEY_FILE holding
        TEST_KEY with mode 0600 in a 0700 keys dir, both owned by the test uid;
        /dev/disk/by-uuid/<PERSONAL_UUID> -> ../../sdb1; sysfs after the open:
        /sys/class/block/sdb1/holders/dm-0, /sys/block/dm-0/dm/name =
        MAPPING_NAME, /sys/class/block/dm-0/slaves/sdb1.
      - FakeRunner script:
        lsblk ... -> 1st fixtures/synthetic/lsblk-tree-personal-locked.json,
                     then fixtures/deck/lsblk-columns-tree.json (dm-0 ntfs)
        findmnt ... --list --real -> fixtures/deck/findmnt-real-list.json
        cryptsetup open --type bitlk --key-file <KEY_FILE> /dev/sdb1
            <MAPPING_NAME> -> rc 0
        ntfs-3g.probe --readwrite /dev/dm-0 -> rc 0
        mount -i -t ntfs3 -o nosuid,nodev,uid=1000,gid=1000,umask=0022,
            windows_names /dev/dm-0 /run/media/deck/PERSONAL -> rc 0
        findmnt ... --mountpoint /run/media/deck/PERSONAL
            -> fixtures/synthetic/findmnt-personal-ntfs3-rw.json
    When
      - reconcile.run(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH,
        Trigger.START)
      - reconcile.run(ctx, InstanceKind.AUTO, DM0_SYSPATH, Trigger.START)
        (the auto instance systemd starts for dm-0 once udev sees ntfs)
    Then (pass criteria)
      - first outcome: route.action == Action.UNLOCK_REGISTERED, state
        MountedRW, reason "" or "clean"; exactly one cryptsetup call equal to
        expected_open_argv with stdin None and secret flag False
      - the record was written with mapping.name == MAPPING_NAME before the
        cryptsetup call (write-ahead, DD-10)
      - record tmp_path/PERSONAL_RECORD: mapping {"name": MAPPING_NAME,
        "kname": "dm-0", "devnum": "252:0", "opened_by": "handler",
        "key_unit_invocation_id": null, "save_pending": false}; mount.device
        "/dev/dm-0", mount.target PERSONAL_PATH, mount.driver "ntfs3"
      - the only mount target in any argv is PERSONAL_PATH; nothing under
        /run/media/deck/PERSONAL-2 or a label-derived path (AC-059)
      - second outcome: route.action == Action.OWN_MAPPING; no new mount,
        probe or cryptsetup call; tmp_path/DM0_RECORD does not exist
      - TEST_KEY never appears in any recorded argv, env value, stdin, caplog
        text, the record or the registry (AC-013; the full sweep lives in
        tests/contract/test_secrets.py)
      - no systemctl start of KEY_UNIT, no loginctl call, no notification
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")


# AC-014: "Given a wrong or missing stored key, when the volume is plugged in,
#   then the stored key is tried once, with no retry loop. list and journald
#   record the unlock failure. The volume stays locked unless the FR-22 dialog
#   succeeds. In Desktop Mode, the FR-22 dialog replaces the 'unlock failed, run
#   set-key' notification for that event."
# AC-075: no Desktop Mode session -> no dialog anywhere, "needs a key"
# DD-18: wrong owner or mode -> NeedsKey reason key_permissions, no dialog
# ROI: 40 (BV:8 x Freq:4 + Legal:0 + Defect:8)
# Behavior: UNLOCK_REGISTERED -> keystore.status -> one open attempt at most ->
#   NeedsKey with the reason -> key unit started (desktop) or nothing (no
#   session / permissions) -> notification only for key_permissions
# @category: core-functionality
# @dependency: reconcile, keystore, bitlocker, session, systemd, notify, state
# @complexity: high
# @real-dependency: tmp_path key file and modes, records, flock
@pytest.mark.parametrize(
    "case",
    ["rejected", "missing", "bad-permissions", "no-session"],
)
def test_stored_key_failure_tried_once_then_key_unit_or_needs_key(
    case: str,
    tmp_path: Path,
) -> None:
    """One attempt, then NeedsKey; the key unit replaces the notification.

    Given (per case)
      - "rejected": key file present and 0600; cryptsetup open -> rc 2;
        loginctl fixtures give the Desktop verdict
      - "missing": no key file; loginctl -> Desktop
      - "bad-permissions": key file mode 0644; loginctl -> Desktop
      - "no-session": key file present, cryptsetup -> rc 2; loginctl show-user
        deck -p Display -> "Display=" (empty, same as absent) -> verdict none
    When
      - reconcile.run(ctx, InstanceKind.REGISTERED, PERSONAL_DEVICE_PATH,
        Trigger.START)
    Then (pass criteria)
      - cryptsetup open is called exactly once for "rejected" and "no-session",
        never for "missing" and "bad-permissions" (AC-014: no retry loop)
      - outcome.state == VolumeState.NEEDS_KEY with reason
        "stored_key_rejected" / "stored_key_missing" / "key_permissions" /
        "no_session" respectively; the record carries the same reason
      - "rejected" and "missing": one systemctl start --no-block KEY_UNIT call
        and no notify-send call (the dialog replaces it, AC-014, AC-046)
      - "bad-permissions": no systemctl start; one notify-send call naming
        PERSONAL whose body points to doctor and then set-key (DD-18, DD-19)
      - "no-session": no systemctl start, no notify-send (Game Mode notification
        deferred, AC-074); state.next_step says "In Desktop Mode, replug ... or
        ... mount --volume PERSONAL ... or ... set-key PERSONAL" (AC-075)
      - no mount, probe or ntfs-3g call in any case; the key file is byte-for-
        byte unchanged where it existed
      - caplog has a NOTICE or WARNING entry with SM_STATE=NeedsKey and the
        reason (AC-041); TEST_KEY appears nowhere in the log
    """
    pytest.skip("skeleton: implement in Phase 3 (mount engine)")
