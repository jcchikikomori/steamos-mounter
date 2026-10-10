"""Exit-code contract (I004): the Design Doc's tables, and the codes commands return.

Design Doc "CLI Contract > Exit Codes" and "Commands"; QA mechanism "Output
contract tests" (exit codes distinct and documented). Both tables are read
from the Design Doc itself, so the test follows the authoritative text:

- ``ExitCode`` equals the Exit Codes table, name for name;
- each implemented command declares exactly its Commands row's codes;
- the scenarios below walk every error path of each implemented command, and
  the set of codes they produce equals that row: no code is promised that
  cannot happen, and none happens that is not promised.

Commands of later phases (``scan``, ``list``, ``set-key``, ``doctor``) join
the walk when they join ``cli.COMMANDS``.
"""

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from steamos_mounter import cli, config, wiring
from steamos_mounter.errors import ExitCode
from tests.helpers.builders import record_dict
from tests.helpers.cli_env import (
    BROKEN_REGISTRY,
    MEDIABOX_PATH,
    MEDIABOX_RECORD,
    MEDIABOX_REGISTRY,
    MEDIABOX_UNIT,
    given_host,
    partition,
    run_cli,
    script_table,
    script_tree,
    script_unit,
    steamos_host,
    tree_with,
    verb_argv,
)
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import SYSTEMCTL, write_record
from tests.helpers.installer_env import (
    INSTANCES,
    KEY_UNITS,
    UDEVADM_RELOAD,
    release_ctx,
    script_reloads,
    stage_release,
    system_tree,
    units_answer,
)

DESIGN_DOC = (
    Path(__file__).resolve().parents[2] / "docs/design/steamos-mounter-design.md"
)
ROW = re.compile(r"^\| (.+) \|$")
MEDIABOX_KEY_UNIT = MEDIABOX_UNIT.replace("steamos-mounter@", "steamos-mounter-key@")


def section(title: str, end: str) -> list[str]:
    text = DESIGN_DOC.read_text(encoding="utf-8")
    start = text.index(f"#### {title}\n")
    return text[start : text.index(end, start)].splitlines()


def table_rows(lines: list[str]) -> list[list[str]]:
    rows = [ROW.match(line) for line in lines]
    cells = [[cell.strip() for cell in row[1].split(" | ")] for row in rows if row]
    return cells[2:]  # after the header and the separator


def documented_exit_codes() -> dict[str, int]:
    rows = table_rows(section("Exit Codes", "#### Commands"))
    return {name: int(code) for code, name, *_rest in rows}


def documented_command_codes() -> dict[str, frozenset[int]]:
    rows = table_rows(section("Commands", "Command behavior that"))
    return {
        name.strip("`"): frozenset(
            int(code) for code in re.findall(r"(?:^|, )(\d)", codes)
        )
        for name, _args, _root, _output, codes in rows
    }


def test_exit_code_equals_the_design_table():
    assert {member.name: int(member) for member in ExitCode} == documented_exit_codes()


def test_the_design_tables_were_read():
    commands = documented_command_codes()
    assert commands["add"] == frozenset({0, 1, 2, 3, 4, 7, 8})
    assert commands["list"] == frozenset({0, 1, 2, 4})
    assert set(commands) == {
        "scan",
        "list",
        "add",
        "remove",
        "set-key",
        "mount",
        "unmount",
        "install",
        "uninstall",
        "doctor",
    }


@pytest.mark.parametrize("name", sorted(cli.BY_NAME))
def test_each_command_declares_its_row(name):
    declared = {int(code) for code in cli.BY_NAME[name].exit_codes}
    assert declared == documented_command_codes()[name]


# --- the error paths ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Env:
    ctx: object
    ctx_deck: object
    root: Path
    runner: object
    host_tree: object


Setup = Callable[[Env], tuple[object, tuple[str, ...]]]


def needs_root(argv: tuple[str, ...]) -> Setup:
    def setup(env: Env):
        steamos_host(env.root)
        return env.ctx_deck, argv

    return setup


def off_steamos(argv: tuple[str, ...]) -> Setup:
    def setup(env: Env):
        steamos_host(env.root, os_id="debian")
        return env.ctx, argv

    return setup


def usage(argv: tuple[str, ...]) -> Setup:
    def setup(env: Env):
        steamos_host(env.root)
        return env.ctx, argv

    return setup


def registry_unusable(argv: tuple[str, ...]) -> Setup:
    def setup(env: Env):
        given_host(env.ctx, env.root, registry=BROKEN_REGISTRY)
        return env.ctx, argv

    return setup


def deck_devices(argv: tuple[str, ...], *, registry: str | None = None) -> Setup:
    def setup(env: Env):
        given_host(env.ctx, env.root, registry=registry)
        env.host_tree.add_sysfs_facts()
        script_tree(env.runner)
        script_table(env.runner)
        return env.ctx, argv

    return setup


def mediabox_absent(argv: tuple[str, ...]) -> Setup:
    def setup(env: Env):
        given_host(env.ctx, env.root, registry=MEDIABOX_REGISTRY)
        script_tree(env.runner, tree_with(partition("sdc1", fstype="exfat")))
        return env.ctx, argv

    return setup


def add_ok(env: Env):
    deck_devices(())(env)
    env.runner.on((SYSTEMCTL, "daemon-reload"), Answer())
    script_unit(env.runner, MEDIABOX_UNIT, "active")
    return env.ctx, ("add", "--device", "/dev/sdb5")


def remove_ok(env: Env, *, busy: tuple[str, ...] = ()):
    given_host(env.ctx, env.root, registry=MEDIABOX_REGISTRY)
    wiring.sync_links(env.ctx, config.load(env.ctx))
    record = record_dict(key="01d95f1575592a30", busy=list(busy), mapping=None)
    write_record(env.root, MEDIABOX_RECORD, json.dumps(record).encode())
    env.runner.on((SYSTEMCTL, "daemon-reload"), Answer(), repeat=True)
    script_unit(env.runner, MEDIABOX_KEY_UNIT, "inactive")
    env.runner.on(verb_argv("stop", MEDIABOX_UNIT, block=True), Answer())
    return env.ctx, ("remove", "MEDIABOX")


def remove_busy(env: Env):
    return remove_ok(env, busy=(MEDIABOX_PATH,))


def mount_ok(env: Env):
    given_host(env.ctx, env.root, registry=MEDIABOX_REGISTRY)
    script_tree(env.runner)
    mounted = record_dict(
        key="01d95f1575592a30",
        state="MountedRW",
        reason=None,
        mapping=None,
        mount={"status": "mounted", "target": MEDIABOX_PATH, "devnum": "8:21"},
    )

    def reconcile(_command) -> None:
        write_record(env.root, MEDIABOX_RECORD, json.dumps(mounted).encode())

    script_unit(env.runner, MEDIABOX_UNIT, "inactive")
    env.runner.on(
        verb_argv("start", MEDIABOX_UNIT, block=True), Answer(), hook=reconcile
    )
    script_table(
        env.runner, Answer.from_fixture("findmnt-list-with-mediabox.json", returncode=0)
    )
    return env.ctx, ("mount", "--volume", "MEDIABOX")


def staged(env: Env):
    """A SteamOS host with a staged release; ctx is that release's entry point."""
    system_tree(env.root)
    release = stage_release(env.root, package=False)
    script_reloads(env.runner)
    return release_ctx(env.ctx, release), release


def install_ok(env: Env):
    run_ctx, release = staged(env)
    return run_ctx, ("install", "--release", str(release), "--no-start")


def install_partial(env: Env):
    _run_ctx, release = staged(env)
    return env.ctx, ("install", "--release", str(release))  # release_root unknown


def uninstall_partial(env: Env):
    system_tree(env.root)
    (env.root / "opt/steamos-mounter").mkdir()  # no current release, no manifest
    return env.ctx, ("uninstall",)


def uninstall_busy(env: Env):
    run_ctx, release = staged(env)
    run_cli(run_ctx, "install", "--release", str(release), "--no-start")
    record = record_dict(key="01d95f1575592a30", busy=[MEDIABOX_PATH])
    write_record(env.root, MEDIABOX_RECORD, json.dumps(record).encode())
    env.runner.on(UDEVADM_RELOAD, Answer())
    env.runner.on(KEY_UNITS, units_answer())
    env.runner.on(INSTANCES, units_answer(MEDIABOX_UNIT))
    env.runner.on(verb_argv("stop", MEDIABOX_UNIT, block=True), Answer())
    return run_ctx, ("uninstall",)


def nothing_installed(env: Env):
    system_tree(env.root)
    return env.ctx, ("uninstall",)


SCENARIOS: dict[str, dict[str, tuple[int, Setup]]] = {
    "add": {
        "registered": (0, add_ok),
        "registry-unusable": (1, registry_unusable(("add", "--device", "/dev/sdb5"))),
        "usage": (2, usage(("add",))),
        "needs-root": (3, needs_root(("add", "--device", "/dev/sdb5"))),
        "off-steamos": (4, off_steamos(("add", "--device", "/dev/sdb5"))),
        "not-attached": (7, deck_devices(("add", "--device", "/dev/sdz9"))),
        "ext4": (8, deck_devices(("add", "--device", "/dev/sda1"))),
    },
    "remove": {
        "removed": (0, remove_ok),
        "registry-unusable": (1, registry_unusable(("remove", "MEDIABOX"))),
        "unknown-name": (2, deck_devices(("remove", "NOPE"))),
        "needs-root": (3, needs_root(("remove", "MEDIABOX"))),
        "off-steamos": (4, off_steamos(("remove", "MEDIABOX"))),
        "busy": (6, remove_busy),
    },
    "mount": {
        "mounted": (0, mount_ok),
        "registry-unusable": (1, registry_unusable(("mount", "--volume", "X"))),
        "usage": (2, usage(("mount",))),
        "needs-root": (3, needs_root(("mount", "--volume", "MEDIABOX"))),
        "off-steamos": (4, off_steamos(("mount", "--volume", "MEDIABOX"))),
        "absent": (7, mediabox_absent(("mount", "--volume", "MEDIABOX"))),
        "ineligible": (8, deck_devices(("mount", "--device", "/dev/sda1"))),
    },
    "unmount": {
        "nothing-to-do": (
            0,
            deck_devices(
                ("unmount", "--volume", "MEDIABOX"), registry=MEDIABOX_REGISTRY
            ),
        ),
        "registry-unusable": (1, registry_unusable(("unmount", "--volume", "X"))),
        "usage": (2, usage(("unmount",))),
        "needs-root": (3, needs_root(("unmount", "--volume", "MEDIABOX"))),
        "off-steamos": (4, off_steamos(("unmount", "--volume", "MEDIABOX"))),
        "absent": (7, mediabox_absent(("unmount", "--volume", "MEDIABOX"))),
    },
    "install": {
        "installed": (0, install_ok),
        "usage": (2, usage(("install", "--bogus"))),
        "needs-root": (3, needs_root(("install",))),
        "off-steamos": (4, off_steamos(("install",))),
        "partial": (5, install_partial),
    },
    "uninstall": {
        "nothing-to-remove": (0, nothing_installed),
        "usage": (2, usage(("uninstall", "--bogus"))),
        "needs-root": (3, needs_root(("uninstall",))),
        "off-steamos": (4, off_steamos(("uninstall",))),
        "partial": (5, uninstall_partial),
        "busy": (6, uninstall_busy),
    },
}
CASES = [
    (command, name, code, setup)
    for command, scenarios in SCENARIOS.items()
    for name, (code, setup) in scenarios.items()
]


def test_every_implemented_command_has_its_error_paths_walked():
    assert set(SCENARIOS) == set(cli.BY_NAME)


@pytest.mark.parametrize("command", sorted(SCENARIOS))
def test_the_walked_codes_equal_the_commands_row(command):
    walked = {code for code, _setup in SCENARIOS[command].values()}
    assert walked == documented_command_codes()[command]


@pytest.mark.parametrize(
    ("command", "name", "code", "setup"),
    CASES,
    ids=[f"{command}-{name}" for command, name, _code, _setup in CASES],
)
def test_each_error_path_returns_its_code(
    ctx, ctx_deck, tmp_path, fake_runner, host_tree, command, name, code, setup
):
    run_ctx, argv = setup(Env(ctx, ctx_deck, tmp_path, fake_runner, host_tree))

    result = run_cli(run_ctx, *argv)

    assert result.code == code, result.err
    assert argv[0] == command
