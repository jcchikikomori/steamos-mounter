"""steamos-mounter on-device E2E journeys (Stage A, B, C) - skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "On-device
Verification Procedure", "Early Verification Point" EVP-2, "Output
Comparison", "On-device Verification Items (V-01 to V-22)"); PRD v1.4 Success
Criteria SM-01 to SM-15. Generated 2026-10-08 by the acceptance-test-generator.
Test type: End-to-End (user-facing multi-step journeys on the owner's Steam
Deck). Implementation timing: after the Phase 4 install for Stage A (EVP-2),
after Phase 5 for Stage B, after the first SteamOS update for Stage C.
Budget used: 8 journeys, at most 2 per feature (FR-02: plug-in and reboot;
FR-04, FR-06, FR-08, FR-11, FR-19, FR-22: one reserved slot each).

These journeys need a Steam Deck, physical actions and sudo, so they cannot run
in Docker and are skipped unless STEAMOS_MOUNTER_DECK=1 is set. Division of
labour (Design Doc "Who does what"): the owner runs every sudo step and every
physical action; the automated part is read-only and runs over SSH from the
development host, never inside the container:

    STEAMOS_MOUNTER_DECK=1 \\
    STEAMOS_MOUNTER_DECK_SSH="ssh -o BatchMode=yes -p 2222 deck@10.0.1.100" \\
    pytest --no-cov tests/e2e

--no-cov is required: the coverage gate (--cov-fail-under=95) is meaningless
for a run that imports nothing from the package. Run the file in order: Stage B
only after Stage A passed, Stage C only after Stage B.

Each journey below is a skeleton: the docstring holds the owner's exact manual
steps, the read-only SSH checks the test will run, and the pass criteria. In
the docstrings "steamos-mounter <command>" stands for the CLI constant (the
absolute path) and "sudo steamos-mounter" for SUDO_CLI. The body skips until
the journey is implemented. Game Mode items (AC-048, AC-074, V-01, V-16, the
Game Mode half of V-20) are "Deferred by owner (Game Mode best effort)" and
have no journey here.
"""

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("STEAMOS_MOUNTER_DECK") != "1",
    reason="on-device E2E: needs a Steam Deck; set STEAMOS_MOUNTER_DECK=1 on the host",
)

REPO = Path(__file__).resolve().parents[2]
DEFAULT_SSH = "ssh -o BatchMode=yes -p 2222 deck@10.0.1.100"
CLI = "/opt/steamos-mounter/bin/steamos-mounter"
SUDO_CLI = f"sudo {CLI}"
JOURNAL = "journalctl -t steamos-mounter --no-pager -o short-iso"
MEDIABOX_UUID = "01D95F1575592A30"
PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
MEDIABOX_UNIT = "steamos-mounter@dev-disk-by\\x2duuid-01D95F1575592A30.service"
PERSONAL_INSTANCE = (
    "dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52\\x2da297\\x2d31643c64724d"
)
PERSONAL_UNIT = f"steamos-mounter@{PERSONAL_INSTANCE}.service"
PERSONAL_KEY_UNIT = f"steamos-mounter-key@{PERSONAL_INSTANCE}.service"
MEDIABOX_PATH = "/run/media/deck/MEDIABOX"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
LATENCY_TARGET_S = 15

# Read-only checks (Design Doc "Who does what"). Every command is safe to run
# as deck over SSH and writes nothing on the Deck.
READ_ONLY_CHECKS = {
    "findmnt": "findmnt -J -o TARGET,SOURCE,FSTYPE,VFS-OPTIONS,FS-OPTIONS,MAJ:MIN",
    "lsblk": "lsblk -J -b -o NAME,KNAME,FSTYPE,LABEL,UUID,MOUNTPOINTS,HOTPLUG",
    "list": f"{CLI} list --json",
    "doctor": f"{CLI} doctor",
    "journal": f"{JOURNAL} --since -10min",
    "failed": "systemctl --failed --no-legend",
    "blame": "systemd-analyze blame --no-pager",
    "ntfs3g": "pgrep -a ntfs-3g || true",
    "dmsetup": "sudo -n dmsetup ls 2>/dev/null || ls /dev/mapper",
    "records": "cat /run/steamos-mounter/records/*/*.json 2>/dev/null || true",
    "acl": "getfacl -p /run/media/deck; stat -c '%U %G %a %n' /run/media/deck",
}


@pytest.fixture(scope="module")
def deck_ssh() -> str:
    """The SSH command prefix for read-only checks (never runs sudo steps)."""
    return os.environ.get("STEAMOS_MOUNTER_DECK_SSH", DEFAULT_SSH)


# User Journey (Stage A): install -> scratch images -> register a loop device ->
#   detach/re-attach -> mounted -> survives daemon-reload and reload -> detach
#   leaves nothing. Gate for everything after it (NFR-16, EVP-2).
# AC-015, AC-016, AC-017, AC-020, AC-069 (chain on clean, dirty, unsafe images);
#   AC-037, AC-045 (install and doctor); V-06, V-08, V-09, V-10, V-11; SM-04
#   (scratch half), SM-11; Output Comparison (tools/compare_mounts.py)
# ROI: 37 (BV:9 x Freq:3 + Legal:0 + Defect:10) | reserved slot: FR-04 journey
# @category: e2e
# @dependency: full-system (Deck, losetup, systemd 261, ntfs-3g 2026.7.7)
# @complexity: high
def test_stage_a_scratch_images_register_mount_reload_survive(
    deck_ssh: str,
) -> None:
    """Stage A on the three scratch images, Desktop Mode.

    Owner steps (sudo or physical)
      1. In Docker: tools/make_scratch_images.sh -> clean.img, dirty.img,
         unsafe.img (64 MiB each); confirm ntfs-3g.probe --readwrite gives 0,
         15 and 14 in Docker (V-10 half).
      2. Copy the images to ~/steamos-mounter-scratch/ on the Deck.
      3. sudo ./install.sh; then sudo steamos-mounter doctor (expect exit 0,
         "Result: all checks passed").
      4. sudo losetup -f --show ~/steamos-mounter-scratch/dirty.img (no
         --partscan) -> /dev/loopN.
      5. sudo steamos-mounter add --device /dev/loopN --name SCRATCH.
      6. sudo losetup -d /dev/loopN; re-attach with the same command (simulated
         plug-in; DD-16, I008).
      7. Old-behaviour baseline once: sudo mkdir /run/smt-old && sudo mount -t
         ntfs /dev/loopN /run/smt-old; after the capture, sudo umount
         /run/smt-old.
      8. V-08 session (SM-11): write 1 GB as deck, idle 30 min, sha256 compare,
         sudo systemctl daemon-reload, sudo systemctl reload of the SCRATCH
         registered instance (steamos-mounter@dev-disk-by\\x2duuid-<SCRATCH
         UUID>.service), compare again; then sudo losetup -d.
      9. Repeat steps 4 to 6 and 9 for clean.img and unsafe.img.
    Read-only checks (this test, over deck_ssh)
      - READ_ONLY_CHECKS["findmnt"], ["list"], ["journal"], ["ntfs3g"],
        ["records"], ["doctor"] after each step above; stat -c '%U %G %a' of
        the mount root and one file written by deck
      - tools/compare_mounts.py on the old and new findmnt captures
    Pass criteria
      - dirty.img: list --json state "MountedRWDirty", driver "ntfs-3g", findmnt
        fstype fuseblk rw with nosuid,nodev; journal shows probe 15, ntfs3
        refused, ntfs-3g mounted (AC-016); files owned by deck (AC-036)
      - the mount and the ntfs-3g process survive daemon-reload, reload and the
        30 min idle; checksums match (AC-020, V-08); after losetup -d: no
        mount, no ntfs-3g process, record NotPresent (AC-031)
      - clean.img: "MountedRW" via ntfs3, no warning (AC-015)
      - unsafe.img: "MountedRO" with the warning text "unsafe state
        (hibernation, Fast Startup, or an abrupt unplug)"; journal lists the
        skipped ntfs3 rw step and the probe code 14 (AC-017, AC-069)
      - compare_mounts.py prints only "equal" and "intended" lines, never
        "UNEXPECTED" (Output Comparison); any UNEXPECTED blocks Stage B
      - failure response (EVP-2): if ntfs-3g dies on reload or daemon-reload,
        stop; ADR-0001 Option C needs an ADR revision before more code
    """
    pytest.skip("skeleton: on-device Stage A journey; see the docstring")


# User Journey (Stage B): plug in MEDIABOX and PERSONAL -> mounted at the fixed
#   paths with no prompt -> surprise unplug -> clean -> replug (10 trials).
# AC-006, AC-010, AC-031, AC-063, AC-079, AC-035; SM-02, SM-06, SM-08; V-05,
#   V-13, V-15, V-18 (suspend/resume with an active mount)
# ROI: 109 (BV:10 x Freq:10 + Legal:0 + Defect:9) | reserved slot: FR-02 journey
# @category: e2e
# @dependency: full-system (Deck, WD drives, udev, systemd, cryptsetup)
# @complexity: high
def test_stage_b_plugin_unplug_replug_registered_volumes(deck_ssh: str) -> None:
    """Hands-free mount at plug-in and clean removal, repeated.

    Preconditions: Stage A passed; sudo steamos-mounter add for MEDIABOX
    (sdb5) and PERSONAL (sdb1, key stored, verified by add); Desktop Mode.
    Owner steps
      1. Plug the WD drive in. Wait until both volumes appear in Dolphin or in
         steamos-mounter list.
      2. Pull the cable without unmounting (surprise unplug), with one file on
         MEDIABOX open in a text editor in trial 3 (V-13).
      3. Repeat 1 and 2 ten times; once through the dock, once through a hub
         (V-15); once suspend and resume with the drive mounted (V-18).
    Read-only checks
      - per trial: READ_ONLY_CHECKS["journal"] to read the kernel/udev
        device-added timestamp and the steamos-mounter "mounted" NOTICE;
        ["findmnt"], ["list"], ["records"] right after mount; ["findmnt"],
        ["dmsetup"], ["ntfs3g"], ["records"] 15 s after unplug; ["failed"]
    Pass criteria
      - 10 of 10 trials: MEDIABOX at MEDIABOX_PATH and PERSONAL at
        PERSONAL_PATH within LATENCY_TARGET_S of the device-added entry
        (SM-02); findmnt shows nosuid,nodev and no noexec (AC-079); the driver
        and mode in list --json equal findmnt's fstype and ro/rw (AC-063)
      - 0 prompts of any kind (password, polkit, key) across all trials
        (SM-08; the stored key works)
      - after every unplug, within 15 s: no mount for either volume, no
        steamos-mounter-* mapping in dmsetup ls, no ntfs-3g process (AC-031,
        SM-06); the deferred close on the open-file trial completes once the
        editor is closed (V-13 records the time)
      - systemctl --failed lists no steamos-mounter unit at any point; one
        mount per plug-in even when udev sends repeated change events
        (AC-035, journal shows "already mounted" for extra reconciles)
    """
    pytest.skip("skeleton: on-device Stage B journey; see the docstring")


# User Journey (Stage B): reboot with the drive attached -> both volumes mounted
#   with no action; reboot without the drive -> boot does not wait, no failed
#   unit.
# AC-007, AC-008; SM-03
# ROI: 71 (BV:9 x Freq:7 + Legal:0 + Defect:8) | second FR-02 slot (ROI > 50)
# @category: e2e
# @dependency: full-system (Deck boot, .device.wants links)
# @complexity: medium
def test_stage_b_reboot_with_and_without_drive(deck_ssh: str) -> None:
    """Cold plug at boot and absent-drive boot.

    Owner steps
      1. With the WD drive attached: reboot the Deck 5 times, log in to
         Desktop Mode, do nothing else.
      2. With the drive detached: reboot 3 times.
    Read-only checks (after each boot)
      - READ_ONLY_CHECKS["findmnt"], ["list"], ["failed"], ["blame"],
        ["journal"] with --boot 0
    Pass criteria
      - 5 of 5 attached boots: both volumes mounted at their fixed paths with
        no user action (AC-007); the journal shows one START reconcile per
        registered instance and no key dialog
      - 3 of 3 detached boots: no steamos-mounter unit in systemctl --failed,
        and no steamos-mounter unit above 1 s in systemd-analyze blame (AC-008,
        SM-03); list --json shows both volumes "NotPresent" with next step
        "Plug the drive in."
      - /run/steamos-mounter exists again after every boot with the manifest
        modes (D002: recreated on the first root entry)
    """
    pytest.skip("skeleton: on-device Stage B journey; see the docstring")


# User Journey (Stage B): stored key removed -> plug in PERSONAL -> dialog in
#   Desktop Mode -> type the key (keyboard and Steam+X) -> mounted -> save
#   question -> Yes once, No/close/timeout/unplug otherwise -> late dialog after
#   a Game Mode boot.
# AC-070, AC-071, AC-072, AC-073, AC-075, AC-076, AC-077, AC-078; SM-15, SM-07;
#   V-02, V-17, V-19, V-21
# ROI: 45 (BV:9 x Freq:4 + Legal:0 + Defect:9) | reserved slot: FR-22 journey
# @category: e2e
# @dependency: full-system (logind, Plasma X11 session, kdialog, user manager)
# @complexity: high
def test_stage_b_key_dialog_desktop_mode(deck_ssh: str) -> None:
    """FR-22 fallback dialog, SM-15 trials.

    Owner steps (each trial starts with the stored key removed:
    sudo rm /var/lib/steamos-mounter/keys/<PERSONAL UUID>.key)
      1. Plug PERSONAL in while in Desktop Mode (3 trials). Type the password
         or the 48-digit recovery key, with and without dashes (V-02); use
         Steam+X for at least one trial (V-17).
      2. At the save question answer: Yes (trial 1), close the window (trial
         2), let it time out 60 s (trial 3).
      3. Cancel trial: press Escape at the password dialog (1 trial).
      4. Wrong-key trial: type a wrong key once (1 trial).
      5. Unplug trial: pull the cable while the dialog is open (1 trial).
      6. Late dialog: boot into Game Mode with PERSONAL attached; switch to
         Desktop Mode; replug (1 trial); then sudo steamos-mounter mount
         --volume PERSONAL (1 trial).
      7. Dolphin race: cancel the dialog, unlock PERSONAL in Dolphin (1 trial).
      8. After all trials: SM-07 search as root for the key bytes in
         journalctl --all, /etc, /var/lib/steamos-mounter (outside keys/),
         /run/steamos-mounter and the /etc update backups.
    Read-only checks
      - READ_ONLY_CHECKS["journal"], ["list"], ["records"], ["findmnt"] after
        each step; systemctl show -p ActiveState,Result PERSONAL_KEY_UNIT;
        systemctl --user list-units 'steamos-mounter-dialog-*' as deck;
        ls -l /var/lib/steamos-mounter/keys (sudo -n, read-only)
    Pass criteria
      - 3 of 3 plug-ins: the dialog naming PERSONAL appears within 15 s and no
        "unlock failed" notification appears next to it (AC-070, AC-014); a
        correct key mounts PERSONAL at PERSONAL_PATH with AC-063 reporting
        (AC-071)
      - Yes stores the key (file root 0600, dir root 0700, AC-011) and the next
        plug-in needs no dialog; close and timeout store nothing, 1 of 1 each
        (AC-072)
      - cancel: list shows "unlock cancelled at the key dialog", nothing
        stored; wrong key: "unlock failed", one journal line, nothing stored
        (AC-073)
      - unplug with the dialog open: the dialog closes, PERSONAL_KEY_UNIT is
        inactive, no dialog unit left in the user manager, nothing stored
        (AC-078); other partitions kept mounting meanwhile
      - Game Mode boot: no dialog, list shows "needs a key" (AC-075); after the
        switch, replug and mount --volume each bring the dialog (1 of 1)
      - Dolphin race: PERSONAL ends at PERSONAL_PATH or list shows "mounted
        elsewhere (at ...)" (AC-060)
      - the SM-07 search finds 0 occurrences of the key (AC-077)
      - V-19 and V-21 facts are recorded in the trial log (kdialog exit codes,
        DISPLAY/XAUTHORITY after a mode switch); a mismatch with the Design
        Doc's transport assumptions is a finding, not a pass/fail item
    """
    pytest.skip("skeleton: on-device Stage B journey; see the docstring")


# User Journey (Stage B): locked unregistered BitLocker stick -> skipped ->
#   unlock in Dolphin -> inner filesystem mounted under /run/media/deck -> and
#   the registered counterpart (PERSONAL unlocked in Dolphin after a failure).
# AC-025, AC-026, AC-060, AC-034; SM-05; V-04
# ROI: 43 (BV:7 x Freq:5 + Legal:0 + Defect:8) | reserved slot: FR-06 journey
# @category: e2e
# @dependency: full-system (udisks2, Dolphin, device-mapper)
# @complexity: high
def test_stage_b_dolphin_unlock_unregistered_and_registered(deck_ssh: str) -> None:
    """Dolphin does the unlock; the tool mounts the inner filesystem.

    Owner steps
      1. Plug in the second (unregistered) BitLocker drive. Wait 15 s.
      2. Unlock it in Dolphin (3 trials; replug between trials). Note whether
         Dolphin shows an error dialog (V-04).
      3. Registered variant: remove PERSONAL's stored key, plug in, cancel
         the dialog, unlock PERSONAL in Dolphin (1 trial).
      4. An exFAT or FAT stick labelled GAMES: plug in 5 times (SM-05 first
         half; also exercises AC-021, AC-024, AC-079 for real).
    Read-only checks
      - READ_ONLY_CHECKS["journal"], ["lsblk"], ["findmnt"], ["list"],
        ["records"], ["dmsetup"], ["acl"] after each step; for AC-079 the
        owner runs a script with its execute bit set from the GAMES stick
    Pass criteria
      - while locked: no unlock attempt, no prompt, journal records "skipped
        while locked", list state "Locked" (AC-025)
      - 3 of 3 Dolphin unlocks: the inner filesystem is mounted at
        /run/media/deck/<sanitized label> within 15 s of the unlock, or, if
        udisks mounted it first, it is not mounted twice and list shows
        "mounted elsewhere (at ...)" (AC-026, AC-034, SM-05)
      - registered variant: PERSONAL ends at PERSONAL_PATH, never under a
        label path (AC-060, AC-059); the key dialog unit stopped when the
        foreign mapping appeared (ADR-0005 D5.2)
      - GAMES: 5 of 5 plug-ins mounted at /run/media/deck/GAMES within 15 s
        with nosuid,nodev, no noexec; /run/media/deck is root 0750 with
        user:1000:r-x (AC-024); the script runs as deck (AC-079)
      - every Dolphin error dialog is recorded in the trial log (accepted v1
        limitation, V-04)
    """
    pytest.skip("skeleton: on-device Stage B journey; see the docstring")


# User Journey (Stage B): "Safely remove" or unmount in Dolphin on a tool-made
#   mount -> no remount until replug -> unplug leaves no mapping; plus the CLI
#   unmount.
# AC-032, AC-033, AC-062; SM-12; V-03, V-07
# ROI: 56 (BV:8 x Freq:6 + Legal:0 + Defect:8) | reserved slot: FR-08 journey
# @category: e2e
# @dependency: full-system (Dolphin, udisks2, systemd reload semantics)
# @complexity: medium
def test_stage_b_safely_remove_respected_until_replug(deck_ssh: str) -> None:
    """The owner's unmount is respected; the mapping is gone by unplug.

    Owner steps
      1. With MEDIABOX and PERSONAL mounted by the tool: "Safely remove" in
         Dolphin (5 cycles, at least 2 on PERSONAL). Note any lock prompt or
         error Dolphin shows for PERSONAL (V-03, V-07).
      2. After each removal wait 30 s, then trigger a change event (e.g. open
         the drive's properties, or sudo udevadm trigger --action=change
         /dev/sdb5) and confirm nothing remounts; then pull the cable; then
         replug.
      3. CLI variant: sudo steamos-mounter unmount --volume MEDIABOX, then the
         same for PERSONAL; then sudo steamos-mounter mount --volume PERSONAL.
    Read-only checks
      - READ_ONLY_CHECKS["findmnt"], ["list"], ["records"], ["dmsetup"],
        ["journal"] after each step
    Pass criteria
      - 5 of 5 cycles: the Dolphin unmount succeeds (AC-032); list shows
        "unmounted by the user"; no remount until replug even after a change
        event (AC-033; journal shows the reload reconcile skipping with
        unmounted_by_user); after unplug, dmsetup ls shows no
        steamos-mounter-* mapping (SM-12)
      - CLI unmount: exit 0, the volume is unmounted, PERSONAL's mapping is
        closed, state "UnmountedByUser"; mount --volume PERSONAL remounts it
        (AC-062, AC-009)
      - Dolphin's lock prompt or error on PERSONAL, if any, is recorded as the
        documented v1 limitation (AC-032, V-03)
    """
    pytest.skip("skeleton: on-device Stage B journey; see the docstring")


# User Journey (Stage B): remove a registration -> doctor passes -> uninstall
#   with a file held open -> busy line, exit 6 -> next boot starts nothing;
#   install a newer build over an active mount (V-22).
# AC-049, AC-065, AC-037, AC-039; SM-14; V-22
# ROI: 29 (BV:7 x Freq:3 + Legal:0 + Defect:8) | reserved slot: FR-19 journey
# @category: e2e
# @dependency: full-system (installer, systemd, udev)
# @complexity: medium
def test_stage_b_remove_update_and_uninstall_clean_undo(deck_ssh: str) -> None:
    """Clean undo of a registration, an in-place update, and the uninstall.

    Owner steps
      1. sudo steamos-mounter remove SCRATCH (the Stage A loop registration),
         then steamos-mounter doctor.
      2. V-22: with MEDIABOX mounted by ntfs-3g, run sudo ./install.sh from a
         checkout with a bumped __version__; then unplug and replug.
      3. Open a file on MEDIABOX in an editor; sudo ./uninstall.sh; close the
         editor; sudo ./uninstall.sh --purge is NOT run (keys kept). Reboot.
    Read-only checks
      - cat /etc/steamos-mounter/config.toml (sudo -n, read-only), ls
        /etc/systemd/system/*.device.wants/, ls /var/lib/steamos-mounter/keys
        (after 1); READ_ONLY_CHECKS["doctor"], ["findmnt"], ["ntfs3g"],
        ["journal"], ["failed"]; ls -l /opt/steamos-mounter/ (after 2); ls
        /opt/steamos-mounter /etc/systemd/system/steamos-mounter* /etc/udev/
        rules.d/90-steamos-mounter.rules /etc/atomic-update.conf.d/ (after 3)
    Pass criteria
      - after remove: 0 config entries, wiring links or key files for SCRATCH;
        doctor exits 0 (AC-049, SM-14)
      - after the update: the old release stays referenced by the running
        ntfs-3g mount until its instance stops; current points at the new
        release; the old record is read by the new release; the unplug
        teardown runs from the new release (V-22); doctor "all checks passed"
      - uninstall with the open file: one "still busy" line and exit 6; after
        the editor closes the lazy unmount completes; 0 steamos-mounter files
        under /opt and /etc apart from kept-config.toml and keys (AC-065,
        SM-14); after the reboot no steamos-mounter unit started and the
        journal filter is empty for that boot
    """
    pytest.skip("skeleton: on-device Stage B journey; see the docstring")


# User Journey (Stage C): the first SteamOS atomic update after install -> no
#   owner action -> config, keys, units and rule still present -> volumes mount
#   at plug-in and boot -> doctor passes -> no manual /etc edit was needed.
# AC-038, AC-043, AC-045, AC-037; SM-01, SM-10, SM-07 (post-update search); V-12
# ROI: 39 (BV:10 x Freq:3 + Legal:0 + Defect:9) | reserved slot: FR-11 journey
# @category: e2e
# @dependency: full-system (SteamOS atomic update, rauc keep-list, holo-sync-var)
# @complexity: high
def test_stage_c_update_survival_without_owner_action(deck_ssh: str) -> None:
    """The install survives a real SteamOS update untouched.

    Owner steps
      1. Before the update: sudo holo-sync-var --dry-run all > before.txt
         (V-12), note the SteamOS build id, keep the WD drive attached.
      2. Apply the SteamOS update from Settings and reboot into Desktop Mode.
         Do not edit anything under /etc.
      3. Plug the drive out and in once; reboot once more with it attached.
      4. Re-run the SM-07 key search as root.
    Read-only checks
      - cat /etc/os-release (build id changed); ls -l of every manifest /etc
        row and the .device.wants links; sudo -n stat of the key files;
        READ_ONLY_CHECKS["doctor"], ["findmnt"], ["list"], ["journal"],
        ["failed"]; diff of before.txt against a fresh holo-sync-var dry run
    Pass criteria
      - every manifest /etc path, both wants links, the registry and the key
        files are present with the same content and modes as before the
        update (AC-038); the dry-run diff lists none of them (V-12, SM-10)
      - after the replug and after the reboot both volumes are mounted at
        their fixed paths with no action (AC-038, SM-01)
      - doctor exits 0 with "all checks passed" as root and "no problems
        found; N checks skipped (need root)" as deck (AC-045, AC-068)
      - the owner confirms 0 manual edits under /etc (SM-01, QM-1); the SM-07
        search finds 0 occurrences of the key, including in the /etc update
        backups
    """
    pytest.skip("skeleton: on-device Stage C journey; see the docstring")
