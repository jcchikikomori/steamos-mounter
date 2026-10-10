"""Setup shared by the key unit's unit, flow and secret-leak tests.

Design Doc "Mock Boundary Decisions": the key unit runs against real files
under ``tmp_path``: the registry, PERSONAL's by-uuid link and its locked
container in sysfs (``flows.lock_sdb1``), the 0700 keys directory, the record
the registered instance leaves behind (``NeedsKey`` with a stored-key
reason), the locks, and the ``/proc`` entries of the Desktop Mode X server
(``ProcTree.desktop``). logind, the user manager, the dialog transport,
cryptsetup and systemctl are scripted on the fake runner with the argv the
package builds.
"""

import logging
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from steamos_mounter.model import InstanceKind, VolumeState
from steamos_mounter.records import update_record
from steamos_mounter.runner import Command
from tests.helpers.builders import MEDIABOX, PERSONAL, registry_text
from tests.helpers.fake_runner import Answer, FakeRunner
from tests.helpers.flows import (
    ACTIVE,
    CRYPTSETUP,
    SYSTEMCTL,
    SYSTEMD_RUN,
    lock_sdb1,
    make_keys_dir,
    make_mount_base,
    make_var_run,
    runtime_dirs,
    script_desktop_session,
    sm_fields,
    write_registry,
)
from tests.helpers.host_tree import HostTree
from tests.helpers.proc_tree import ProcTree

if TYPE_CHECKING:
    from steamos_mounter.context import Context

PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
MEDIABOX_UUID = "01D95F1575592A30"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
PERSONAL_DEVICE_PATH = f"/dev/disk/by-uuid/{PERSONAL_UUID}"
PERSONAL_RECORD = f"run/steamos-mounter/records/registered/{PERSONAL_UUID}.json"
PERSONAL_INSTANCE = (
    "dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52\\x2da297\\x2d31643c64724d"
)
REGISTERED_UNIT = f"steamos-mounter@{PERSONAL_INSTANCE}.service"
KEY_UNIT = f"steamos-mounter-key@{PERSONAL_INSTANCE}.service"
DIALOG_SERVICE = f"steamos-mounter-dialog-{PERSONAL_UUID}.service"
MAPPING_NAME = f"steamos-mounter-{PERSONAL_UUID}"
KEY_FILE = f"var/lib/steamos-mounter/keys/{PERSONAL_UUID}.key"
VOLUME_LOCK = f"run/steamos-mounter/locks/volume-{PERSONAL_UUID}.lock"
DIALOG_LOCK = "run/steamos-mounter/locks/dialog.lock"
TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"
CLI_ROOT = "sudo /opt/steamos-mounter/bin/steamos-mounter"

SHOW_ENVIRONMENT = (SYSTEMCTL, "--user", "show-environment")
MANAGER_ENVIRONMENT = Answer(stdout=b"DISPLAY=:0\nOTHER=dropped\n")
USER_STOP = (SYSTEMCTL, "--user", "stop")
LEFTOVER_STOP = (SYSTEMCTL, "--user", "stop", DIALOG_SERVICE)
DIALOG_STOP = (SYSTEMCTL, "--user", "stop", "--no-block", DIALOG_SERVICE)
NOT_LOADED = Answer(returncode=5, stderr=b"Unit not loaded.")
RELOAD_REGISTERED = (SYSTEMCTL, "reload", "--no-block", "--", REGISTERED_UNIT)
STOP_KEY_UNIT = (SYSTEMCTL, "stop", "--no-block", "--", KEY_UNIT)
SESSION_ENV = {
    "XDG_RUNTIME_DIR": "/run/user/1000",
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
}
ENTERED = Answer(stdout=TEST_KEY + b"\n")
YES = Answer()
NO = Answer(returncode=1)
LOGGER = "steamos_mounter.keyunit"

Hook = Callable[[Command], None]


def is_password(command: Command) -> bool:
    return command.argv[0] == SYSTEMD_RUN and "--password" in command.argv


def is_save(command: Command) -> bool:
    return command.argv[0] == SYSTEMD_RUN and "--yesno" in command.argv


def is_notify(command: Command) -> bool:
    return tuple(command.argv[:3]) == (SYSTEMD_RUN, "--user", "--wait")


def is_registered_show(command: Command) -> bool:
    argv = tuple(command.argv)
    return argv[:2] == (SYSTEMCTL, "show") and argv[-1] == REGISTERED_UNIT


def given_key_unit_started(
    ctx: "Context",
    tmp_path: Path,
    host_tree: HostTree,
    *,
    reason: str | None = "stored_key_rejected",
) -> Callable[[Command], None]:
    """PERSONAL plugged in locked after the registered instance started the key unit.

    The registry holds MEDIABOX and PERSONAL; the record says ``NeedsKey``
    with ``reason`` (None: no record); no key file; the Desktop Mode X
    server is in ``/proc``. Returns the hook that does to sysfs what
    ``cryptsetup open`` does.
    """
    runtime_dirs(ctx)
    write_registry(tmp_path, registry_text([MEDIABOX, PERSONAL]))
    host_tree.add_sysfs_facts()
    host_tree.link_by_uuid(PERSONAL_UUID, "sdb1")
    host_tree.link_by_uuid(MEDIABOX_UUID, "sdb5")
    make_mount_base(tmp_path)
    make_var_run(tmp_path)
    make_keys_dir(tmp_path)
    ProcTree(tmp_path).desktop()
    if reason is not None:
        write_needs_key_record(ctx, reason)
    return lock_sdb1(tmp_path, MAPPING_NAME)


def write_needs_key_record(ctx: "Context", reason: str) -> None:
    """The record ``reconcile_unlock`` leaves when it starts the key unit."""

    def needs_key(record) -> None:
        record.name = "PERSONAL"
        record.unit = REGISTERED_UNIT
        record.state = VolumeState.NEEDS_KEY
        record.reason = reason
        record.source = {"kname": "sdb1", "devnum": "8:17", "syspath": None}

    update_record(ctx, InstanceKind.REGISTERED, PERSONAL_UUID, needs_key)


def script_session(runner: FakeRunner) -> None:
    """Desktop Mode on ``:0`` for every session check; no leftover dialog unit."""
    script_desktop_session(runner)
    runner.on(SHOW_ENVIRONMENT, MANAGER_ENVIRONMENT, repeat=True)
    runner.on(USER_STOP, NOT_LOADED, repeat=True)


def script_reload(runner: FakeRunner, *, on_reload: Hook | None = None) -> None:
    """The registered instance is active and takes the reload request."""
    runner.on(is_registered_show, Answer(stdout=ACTIVE.encode()), repeat=True)
    runner.on(RELOAD_REGISTERED, Answer(), hook=on_reload, repeat=True)


def script_key_unit_flow(
    runner: FakeRunner,
    opened: Hook,
    *,
    password: Answer = ENTERED,
    save: Answer = NO,
    open_rc: int = 0,
    hooks: Mapping[str, Hook] | None = None,
) -> None:
    """Session, the two questions, one cryptsetup open, the reload and notify-send.

    ``opened`` runs on a successful open (``open_rc`` 0). ``hooks`` may name
    a hook for ``"password"``, ``"open"`` (replacing ``opened``), ``"reload"``
    and ``"save"``.
    """
    hooks = hooks or {}
    on_open = hooks.get("open", opened if open_rc == 0 else None)
    script_session(runner)
    runner.on(is_password, password, hook=hooks.get("password"))
    runner.on(CRYPTSETUP, Answer(returncode=open_rc), hook=on_open)
    script_reload(runner, on_reload=hooks.get("reload"))
    runner.on(is_save, save, hook=hooks.get("save"))
    runner.on(is_notify, Answer(), repeat=True)


def key_found_outside(runner: FakeRunner, caplog, tmp_path: Path) -> bool:
    """TEST_KEY anywhere but cryptsetup's stdin and the key file.

    Argv items, environment values, every other stdin, the caplog text and
    ``SM_*`` fields, every runtime record and the registry. A boolean, so a
    failing assertion never prints the key.
    """
    text = TEST_KEY.decode()
    in_calls = any(
        text in item
        for call in runner.calls
        for item in (*call.argv, *call.env_extra.values())
    ) or any(
        call.stdin is not None and TEST_KEY in call.stdin
        for call in runner.calls
        if call.argv[0] != CRYPTSETUP
    )
    records: list[logging.LogRecord] = caplog.records
    in_logs = text in caplog.text or any(
        text in str(sm_fields(record)) for record in records
    )
    state_files = [*(tmp_path / "run/steamos-mounter").rglob("*.json")]
    state_files.append(tmp_path / "etc/steamos-mounter/config.toml")
    in_files = any(TEST_KEY in path.read_bytes() for path in state_files)
    return in_calls or in_logs or in_files
