"""Setup shared by the CLI tests: a SteamOS host tree and the systemctl answers.

Design Doc "Mock Boundary Decisions": the host tree is real files under
``tmp_path``, external commands are scripted on the ``FakeRunner``. The CLI
runs through ``cli.main`` with an injected ``Context`` and an ``Output`` on
string streams, so a test sees exactly the lines and the exit code an owner
would. Unit names are written out as systemd escapes them (the Deck capture
``systemd-escape.tsv``), not computed by the package.
"""

import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from steamos_mounter import cli
from steamos_mounter.output import Output
from tests.helpers.builders import lsblk_device, lsblk_tree
from tests.helpers.fake_runner import Answer, FakeRunner
from tests.helpers.fixtures import load_fixture
from tests.helpers.flows import (
    LSBLK_ARGV,
    SETFACL,
    SYSTEMCTL,
    TABLE_ARGV,
    known_os_set,
    make_mount_base,
    runtime_dirs,
    write_registry,
)

OS_RELEASE = "etc/os-release"
SYSTEMD_SYSTEM = "etc/systemd/system"
REGISTRY_FILE = "etc/steamos-mounter/config.toml"
CLI = "sudo /opt/steamos-mounter/bin/steamos-mounter"
DETAILS = "Details: journalctl -t steamos-mounter"

MEDIABOX_UUID = "01D95F1575592A30"
MEDIABOX_PATH = "/run/media/deck/MEDIABOX"
MEDIABOX_INSTANCE = "dev-disk-by\\x2duuid-01D95F1575592A30"
MEDIABOX_UNIT = f"steamos-mounter@{MEDIABOX_INSTANCE}.service"
MEDIABOX_LINK = f"{SYSTEMD_SYSTEM}/{MEDIABOX_INSTANCE}.device.wants/{MEDIABOX_UNIT}"
MEDIABOX_RECORD = "run/steamos-mounter/records/registered/01d95f1575592a30.json"
PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
PERSONAL_INSTANCE = (
    "dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52\\x2da297\\x2d31643c64724d"
)
PERSONAL_UNIT = f"steamos-mounter@{PERSONAL_INSTANCE}.service"
PERSONAL_KEY_UNIT = f"steamos-mounter-key@{PERSONAL_INSTANCE}.service"
PERSONAL_RECORD = f"run/steamos-mounter/records/registered/{PERSONAL_UUID}.json"
PERSONAL_KEY = f"var/lib/steamos-mounter/keys/{PERSONAL_UUID}.key"

DAEMON_RELOAD = (SYSTEMCTL, "daemon-reload")
REAL_TABLE = "findmnt-real-list.json"
DECK_TREE = "lsblk-columns-tree.json"
MEDIABOX_REGISTRY = """\
schema_version = 1

[[volume]]
name = "MEDIABOX"
uuid = "01D95F1575592A30"
path = "/run/media/deck/MEDIABOX"
fstype = "ntfs"
nosuid = true
nodev = true
"""
PERSONAL_REGISTRY = """\
schema_version = 1

[[volume]]
name = "PERSONAL"
uuid = "658207d5-5177-4a52-a297-31643c64724d"
path = "/run/media/deck/PERSONAL"
fstype = "BitLocker"
nosuid = true
nodev = true
"""
BROKEN_REGISTRY = "schema_version = 9\n"


@dataclass(frozen=True, slots=True)
class CliRun:
    code: int
    out: str
    err: str


def run_cli(ctx, *argv: str) -> CliRun:
    """``cli.main(argv)`` on string streams."""
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), ctx=ctx, out=Output(out=out, err=err))
    return CliRun(code, out.getvalue(), err.getvalue())


def steamos_host(root: Path, *, os_id: str = "steamos") -> None:
    """``/etc/os-release`` with ``ID=<os_id>`` and ``/run`` (tmpfs on the Deck)."""
    path = root / OS_RELEASE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'NAME="test"\nID={os_id}\n', encoding="utf-8")
    (root / "run").mkdir(exist_ok=True)


def given_host(
    ctx,
    root: Path,
    *,
    registry: str | None = None,
    os_set: bool = True,
    mount_base: bool = True,
) -> None:
    """A SteamOS host as root after install: registry dir, wiring dir, ``/run``.

    ``registry`` None leaves ``config.toml`` absent (the empty registry).
    """
    steamos_host(root)
    runtime_dirs(ctx)
    write_registry(root, registry)
    (root / SYSTEMD_SYSTEM).mkdir(parents=True, exist_ok=True)
    if os_set:
        known_os_set(root)
    if mount_base:
        make_mount_base(root)


def show_argv(unit: str) -> tuple[str, ...]:
    return (SYSTEMCTL, "show", "--property=LoadState,ActiveState", "--", unit)


def unit_state(active_state: str) -> Answer:
    return Answer(stdout=f"LoadState=loaded\nActiveState={active_state}\n".encode())


def script_unit(runner: FakeRunner, unit: str, *states: str) -> None:
    """``systemctl show`` of ``unit`` answers ``states`` in order, the last repeated."""
    runner.on(show_argv(unit), *(unit_state(item) for item in states), repeat=True)


def verb_argv(verb: str, unit: str, *, block: bool) -> tuple[str, ...]:
    options = () if block else ("--no-block",)
    return (SYSTEMCTL, verb, *options, "--", unit)


def script_tree(runner: FakeRunner, document: dict[str, Any] | None = None) -> None:
    """Every lsblk call answers ``document`` (default: the Deck capture)."""
    data = (
        load_fixture(DECK_TREE) if document is None else json.dumps(document).encode()
    )
    runner.on(LSBLK_ARGV, Answer(stdout=data), repeat=True)


def script_table(runner: FakeRunner, *answers: Answer) -> None:
    """Every ``findmnt --list --real``: ``answers`` in order, the last repeated."""
    runner.on(TABLE_ARGV, *(answers or (Answer.from_fixture(REAL_TABLE),)), repeat=True)


def script_setfacl(runner: FakeRunner, returncode: int = 0) -> None:
    runner.on(SETFACL, Answer(returncode=returncode))


def systemctl_calls(runner: FakeRunner) -> list[tuple[str, ...]]:
    return [argv for argv in runner.argvs if argv[0] == SYSTEMCTL]


def tree_with(*devices: dict[str, Any]) -> dict[str, Any]:
    """An lsblk document of ``devices`` (``builders.lsblk_device`` nodes)."""
    return lsblk_tree(devices)


def partition(kname: str, **columns: Any) -> dict[str, Any]:
    """A removable partition node; ``columns`` override the builder's defaults."""
    return lsblk_device(kname, {"hotplug": True, **columns})


def files_under(root: Path) -> list[str]:
    """Every path under ``root``, relative and sorted: a snapshot of the tree."""
    return sorted(str(path.relative_to(root)) for path in root.rglob("*"))


def findmnt_rows(*rows: tuple[str, str, str, str]) -> Answer:
    """A ``findmnt --json`` answer of ``(target, source, fstype, maj:min)`` rows."""
    filesystems = [
        {
            "target": target,
            "source": source,
            "fstype": fstype,
            "vfs-options": "rw,nosuid,nodev,relatime",
            "fs-options": "rw",
            "maj:min": devnum,
        }
        for target, source, fstype, devnum in rows
    ]
    return Answer(stdout=json.dumps({"filesystems": filesystems}).encode())
