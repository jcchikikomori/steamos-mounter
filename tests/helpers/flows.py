"""Setup shared by the reconcile unit tests and the flow integration tests.

Design Doc "Mock Boundary Decisions": the host tree is real files under
``tmp_path`` (``HostPaths(root=tmp_path)``), so a flow needs the registry
directory, the mount base, holo's ``/var/run`` and the OS partition sources
as files with the owners and modes the package checks. External commands
are scripted on the ``FakeRunner`` with the argv the package builds; the
constants below are those argv prefixes.
"""

import json
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from steamos_mounter import records
from steamos_mounter.blockdev import LSBLK_COLUMNS
from steamos_mounter.mounts import FINDMNT_COLUMNS
from steamos_mounter.platforms.steamos import TOOLS
from steamos_mounter.runner import Command
from tests.helpers.fake_runner import Answer, FakeRunner
from tests.helpers.fixtures import load_fixture

if TYPE_CHECKING:
    from steamos_mounter.context import Context

LSBLK_ARGV = (TOOLS.lsblk, "--json", "--bytes", "--tree", "-o", LSBLK_COLUMNS)
TABLE_ARGV = (TOOLS.findmnt, "--json", "-o", FINDMNT_COLUMNS, "--list", "--real")
PROBE = TOOLS.ntfs3g_probe
MOUNT = TOOLS.mount
NTFS3G = TOOLS.ntfs3g
SETFACL = TOOLS.setfacl
SYSTEMCTL = TOOLS.systemctl
LOGINCTL = TOOLS.loginctl
SYSTEMD_RUN = TOOLS.systemd_run
CRYPTSETUP = TOOLS.cryptsetup
DMSETUP = TOOLS.dmsetup

REGISTRY_DIR = "etc/steamos-mounter"
HOLO_RULES = "run/udev/rules.d/90-holo-partsets-all.rules"
HOLO_RULES_FIXTURE = "udev-run-90-holo-partsets-all.rules.txt"
MOUNT_BASE = "run/media/deck"
VAR_RUN = "var/run"
RECORDS = "run/steamos-mounter/records"
FIELDS = "sm_fields"
ACTIVE = "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\n"
INACTIVE = "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\n"


def readback_argv(target: str) -> tuple[str, ...]:
    """``findmnt --mountpoint <target>``, the chain's read-back."""
    return (TOOLS.findmnt, "--json", "-o", FINDMNT_COLUMNS, "--mountpoint", target)


def runtime_dirs(ctx: "Context") -> None:
    """``/run`` (tmpfs on the Deck), then the tree every root entry creates (D002)."""
    ctx.paths.p("/run").mkdir(exist_ok=True)
    records.ensure_runtime_dirs(ctx)


def write_registry(root: Path, text: str | None) -> None:
    """``/etc/steamos-mounter`` (0755) and, unless ``text`` is None, ``config.toml``."""
    directory = root / REGISTRY_DIR
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    if text is not None:
        path = directory / "config.toml"
        path.write_text(text, encoding="utf-8")
        path.chmod(0o644)


def make_mount_base(root: Path) -> Path:
    """``/run/media`` (0755) and the mount base (0750), as udisks leaves them."""
    base = root / MOUNT_BASE
    base.mkdir(parents=True, exist_ok=True)
    base.parent.chmod(0o755)
    base.chmod(0o750)
    return base


def make_var_run(root: Path) -> Path:
    """``/var/run``, where holo's per-device lock files live."""
    path = root / VAR_RUN
    path.mkdir(parents=True, exist_ok=True)
    return path


def known_os_set(root: Path) -> None:
    """holo's rules file from the Deck capture: the OS partition set is known."""
    path = root / HOLO_RULES
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(load_fixture(HOLO_RULES_FIXTURE))


def script_lsblk(runner: FakeRunner, fixture: str) -> None:
    """Every lsblk call answers with ``fixture``."""
    runner.on(LSBLK_ARGV, Answer.from_fixture(fixture, returncode=0), repeat=True)


def script_desktop_session(runner: FakeRunner) -> None:
    """logind answers for the Deck's Desktop Mode session 5 (Desktop verdict)."""
    runner.on((LOGINCTL, "show-user"), "loginctl-user-deck.txt", repeat=True)
    runner.on((LOGINCTL, "show-seat"), "loginctl-seat-seat0-active.txt", repeat=True)
    runner.on(
        (LOGINCTL, "show-session"), "loginctl-session-5-properties.txt", repeat=True
    )


def script_no_session(runner: FakeRunner) -> None:
    """``deck`` has no graphical session (Game Mode or logged out): verdict NONE."""
    runner.on((LOGINCTL, "show-user"), Answer(stdout=b"Display=\n"), repeat=True)


def script_notify(runner: FakeRunner) -> None:
    runner.on((SYSTEMD_RUN, "--user"), Answer(), repeat=True)


def write_record(root: Path, relative: str, payload: bytes) -> Path:
    """A record file (0644) holding ``payload`` as is: valid JSON or garbage."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o644)
    return path


def make_leaf(root: Path, target: str) -> Path:
    """The mount base and an empty leaf directory at ``target``."""
    make_mount_base(root)
    leaf = root / target.lstrip("/")
    leaf.mkdir()
    return leaf


def read_record(root: Path, relative: str) -> dict[str, Any]:
    return json.loads((root / relative).read_text(encoding="utf-8"))


def sm_fields(record: logging.LogRecord) -> dict[str, str]:
    """The ``SM_*`` fields a log call passed through ``journal.fields``."""
    return dict(getattr(record, FIELDS, {}))


def argvs_of(runner: FakeRunner, tool: str) -> list[tuple[str, ...]]:
    return [argv for argv in runner.argvs if argv[0] == tool]


# --- BitLocker: key files, the locked container, the key unit (P3-T06) -----------

KEYS_DIR = "var/lib/steamos-mounter/keys"
KEY_UNIT_PREFIX = "steamos-mounter-key@"
SDB1_DM0_HOLDER = "sys/class/block/sdb1/holders/dm-0"
DM0_NAME = "sys/block/dm-0/dm/name"


def write_key_file(root: Path, uuid: str, data: bytes, *, mode: int = 0o600) -> Path:
    """``keys/<uuid>.key`` with ``mode`` in the 0700 keys directory, test uid."""
    directory = root / KEYS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    path = directory / f"{uuid}.key"
    path.write_bytes(data)
    path.chmod(mode)
    return path


def make_keys_dir(root: Path) -> Path:
    """The installer's empty 0700 keys directory: a stored key is missing."""
    directory = root / KEYS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    return directory


def lock_sdb1(root: Path, mapping_name: str) -> Callable[[Command], None]:
    """PERSONAL's container locked: sdb1 loses its dm-0 holder in sysfs.

    The returned hook is what ``cryptsetup open`` does to sysfs: dm-0 holds
    sdb1 again, named ``mapping_name``.
    """
    holder = root / SDB1_DM0_HOLDER
    target = os.readlink(holder)
    holder.unlink()

    def opened(_command: Command) -> None:
        holder.symlink_to(target)
        (root / DM0_NAME).write_text(f"{mapping_name}\n", encoding="utf-8")

    return opened


def key_unit_show(active_state: str, invocation_id: str = "") -> Answer:
    """``systemctl show`` of a key unit: loaded, ``active_state``, its InvocationID."""
    text = (
        f"LoadState=loaded\nActiveState={active_state}\nInvocationID={invocation_id}\n"
    )
    return Answer(stdout=text.encode())


def script_key_unit(runner: FakeRunner, answer: Answer | None = None) -> None:
    """Every ``systemctl show`` of a key unit answers ``answer`` (default inactive)."""
    runner.on(_is_key_unit_show, answer or key_unit_show("inactive"), repeat=True)


def _is_key_unit_show(command: Command) -> bool:
    argv = tuple(command.argv)
    return argv[:2] == (SYSTEMCTL, "show") and argv[-1].startswith(KEY_UNIT_PREFIX)
