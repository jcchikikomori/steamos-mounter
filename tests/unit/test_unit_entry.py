"""unit_entry: the internal verbs, their guards and the exit-0 discipline.

Design Doc "CLI Contract > Internal Verbs" (DD-03, D011, D002), "Exit
Codes", the EARS block "Entry, Verbs and Guards" ("an ``internal`` verb
without root exits 3; without ``INVOCATION_ID`` exits 2; nothing changes"),
IP-03 and AC-030; ADR-0001 (a unit exits 0 after a decided outcome). The
host tree is real files under ``tmp_path``; external commands go through the
fake runner, whose call log must stay empty wherever a guard or a rejection
stops the run. The core entries (``reconcile.run``, ``teardown.stop`` and
``sweep``, ``keyunit.run`` and ``stop_post``) are replaced by recorders where
a test is about dispatch; the real ones run where the outcome needs no
external command.
"""

import ast
import dataclasses
import io
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from steamos_mounter import keyunit, reconcile, records, teardown, unit_entry
from steamos_mounter.errors import UnsupportedPlatformError
from steamos_mounter.locks import LockTimeout
from steamos_mounter.model import InstanceKind, Trigger
from steamos_mounter.sensitive import SecretBytes
from steamos_mounter.teardown import ServiceResult
from tests.helpers.builders import record_dict
from tests.helpers.flows import read_record, write_record

PERSONAL_UUID = "658207d5-5177-4a52-a297-31643c64724d"
REGISTERED = f"/dev/disk/by-uuid/{PERSONAL_UUID}"
AUTO = "/sys/devices/host-tree/block/sdb/sdb1"
PERSONAL_RECORD = f"run/steamos-mounter/records/registered/{PERSONAL_UUID}.json"
AUTO_KEY = "sdb1-8_17"
AUTO_RECORD = f"run/steamos-mounter/records/auto/{AUTO_KEY}.json"
RUNTIME_TREE = "run/steamos-mounter"
CLI = "sudo /opt/steamos-mounter/bin/steamos-mounter"
SOURCE = Path(unit_entry.__file__)

VERB_ARGVS = {
    "reconcile": (
        "internal",
        "reconcile",
        "--trigger",
        "start",
        "registered",
        REGISTERED,
    ),
    "teardown": ("internal", "teardown", "auto", AUTO),
    "sweep": ("internal", "sweep", "registered", REGISTERED),
    "key": ("internal", "key", REGISTERED),
    "key-stop": ("internal", "key-stop", REGISTERED),
}
VERBS = tuple(VERB_ARGVS)
SERVICE_ENV = {
    "SERVICE_RESULT": "timeout",
    "EXIT_CODE": "killed",
    "EXIT_STATUS": "TERM",
}
SERVICE = ServiceResult(result="timeout", exit_code="killed", exit_status="TERM")
TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"


class Core:
    """Records every call to the five core entries; may raise instead."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.error: BaseException | None = None

    def recorder(self, name: str):
        def called(_ctx: object, *args: object) -> None:
            self.calls.append((name, *args))
            if self.error is not None:
                raise self.error

        return called


@pytest.fixture
def core(monkeypatch: pytest.MonkeyPatch) -> Core:
    spy = Core()
    monkeypatch.setattr(reconcile, "run", spy.recorder("reconcile.run"))
    monkeypatch.setattr(teardown, "stop", spy.recorder("teardown.stop"))
    monkeypatch.setattr(teardown, "sweep", spy.recorder("teardown.sweep"))
    monkeypatch.setattr(keyunit, "run", spy.recorder("keyunit.run"))
    monkeypatch.setattr(keyunit, "stop_post", spy.recorder("keyunit.stop_post"))
    return spy


def write_os_release(root: Path, os_id: str) -> None:
    path = root / "etc/os-release"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'NAME="test"\nID={os_id}\n', encoding="utf-8")


@pytest.fixture
def steamos(tmp_path: Path) -> Path:
    """A SteamOS host with ``/run`` (tmpfs on the Deck) and nothing else yet."""
    write_os_release(tmp_path, "steamos")
    (tmp_path / "run").mkdir()
    return tmp_path


def run_verb(verb: str, ctx) -> int:
    return unit_entry.main(list(VERB_ARGVS[verb]), ctx=ctx)


def errors_logged(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.levelno >= logging.ERROR]


# --- guards ---------------------------------------------------------------------------


@pytest.mark.parametrize("verb", VERBS)
def test_each_verb_as_deck_exits_3_and_changes_nothing(
    verb, steamos, ctx_deck, core, fake_runner, capsys
):
    code = run_verb(verb, ctx_deck)

    assert code == 3
    assert fake_runner.calls == []
    assert core.calls == []
    assert not (steamos / RUNTIME_TREE).exists()
    assert capsys.readouterr().err == "steamos-mounter: internal command: needs root.\n"


@pytest.mark.parametrize("verb", VERBS)
def test_each_verb_as_root_without_invocation_id_exits_2_and_changes_nothing(
    verb, steamos, ctx, core, fake_runner, capsys
):
    from_a_shell = dataclasses.replace(ctx, invocation_id=None)

    code = run_verb(verb, from_a_shell)

    assert code == 2
    assert fake_runner.calls == []
    assert core.calls == []
    assert not (steamos / RUNTIME_TREE).exists()
    assert capsys.readouterr().err == (
        "steamos-mounter: internal command: started by systemd only.\n"
    )


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("who", ["root", "deck"])
def test_each_verb_on_debian_exits_4_before_the_root_check(
    verb, who, tmp_path, ctx, ctx_deck, core, fake_runner, capsys
):
    write_os_release(tmp_path, "debian")
    (tmp_path / "run").mkdir()

    code = run_verb(verb, ctx if who == "root" else ctx_deck)

    assert code == 4
    assert fake_runner.calls == []
    assert core.calls == []
    assert not (tmp_path / RUNTIME_TREE).exists()
    assert capsys.readouterr().err == (
        "steamos-mounter: unsupported platform: SteamOS only.\n"
    )


def test_a_malformed_argv_from_deck_still_gets_the_root_exit(steamos, ctx_deck, core):
    assert unit_entry.main(["internal", "mount", "--volume", "X"], ctx=ctx_deck) == 3


def test_on_the_host_the_guards_read_the_platform_first(monkeypatch, core, capsys):
    def not_steamos() -> None:
        raise UnsupportedPlatformError("unsupported platform: SteamOS only")

    monkeypatch.setattr(unit_entry, "current_platform", not_steamos)
    monkeypatch.setattr(unit_entry.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", "0f6c9c1e5c7a4c51a0a5f3f3b2b6d7e8")

    assert run_verb("key", None) == 4
    assert core.calls == []


@pytest.mark.parametrize(
    ("euid", "invocation_id", "code"), [(1000, "abc", 3), (0, None, 2), (0, "", 2)]
)
def test_on_the_host_the_guards_read_euid_then_invocation_id(
    monkeypatch, core, euid, invocation_id, code
):
    monkeypatch.setattr(unit_entry, "current_platform", lambda: None)
    monkeypatch.setattr(unit_entry.os, "geteuid", lambda: euid)
    if invocation_id is None:
        monkeypatch.delenv("INVOCATION_ID", raising=False)
    else:
        monkeypatch.setenv("INVOCATION_ID", invocation_id)

    assert run_verb("reconcile", None) == code
    assert core.calls == []


# --- the context ----------------------------------------------------------------------


def started_by_systemd(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(unit_entry, "current_platform", lambda: None)
    monkeypatch.setattr(unit_entry.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", "0f6c9c1e5c7a4c51a0a5f3f3b2b6d7e8")


@pytest.mark.parametrize(
    ("argv", "component"),
    [
        (VERB_ARGVS["reconcile"], "handler"),
        (VERB_ARGVS["sweep"], "handler"),
        (VERB_ARGVS["key"], "key-unit"),
        (VERB_ARGVS["key-stop"], "key-unit"),
        (("internal", "key", "/dev/sdb1"), "key-unit"),
        (("internal", "mount"), "handler"),
    ],
)
def test_on_the_host_the_context_is_built_for_the_verbs_component(
    monkeypatch, steamos, ctx, core, argv, component
):
    started_by_systemd(monkeypatch)
    built: list[str] = []

    def build_context(*, component: str):
        built.append(component)
        return ctx

    monkeypatch.setattr(unit_entry, "build_context", build_context)

    assert unit_entry.main(list(argv)) == 0
    assert built == [component]


def test_a_failing_context_build_is_logged_and_exits_0(
    monkeypatch, core, fake_runner, caplog
):
    started_by_systemd(monkeypatch)

    def build_context(*, component: str):
        raise RuntimeError("journal socket gone")

    monkeypatch.setattr(unit_entry, "build_context", build_context)

    assert run_verb("teardown", None) == 0
    assert core.calls == []
    assert fake_runner.calls == []
    [entry] = errors_logged(caplog)
    assert "journal socket gone" in entry.getMessage()
    assert entry.exc_info is not None


def test_an_untrusted_runtime_tree_fails_closed_with_no_device_action(
    steamos, ctx, core, fake_runner, caplog
):
    elsewhere = steamos / "elsewhere"
    elsewhere.mkdir()
    (steamos / RUNTIME_TREE).symlink_to(elsewhere)

    code = run_verb("reconcile", ctx)

    assert code == 0
    assert core.calls == []
    assert fake_runner.calls == []
    [entry] = errors_logged(caplog)
    assert "runtime state directory cannot be trusted" in entry.getMessage()
    assert not entry.exc_info
    assert list(elsewhere.iterdir()) == []


def test_a_passing_run_creates_the_runtime_tree(steamos, ctx, core):
    run_verb("key", ctx)

    for absolute, _mode in records.RUNTIME_DIRS:
        assert (steamos / absolute.lstrip("/")).is_dir()


# --- parsing and dispatch -------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (
            VERB_ARGVS["reconcile"],
            ("reconcile.run", InstanceKind.REGISTERED, REGISTERED, Trigger.START),
        ),
        (
            ("internal", "reconcile", "--trigger", "reload", "auto", AUTO),
            ("reconcile.run", InstanceKind.AUTO, AUTO, Trigger.RELOAD),
        ),
        (VERB_ARGVS["teardown"], ("teardown.stop", InstanceKind.AUTO, AUTO)),
        (
            ("internal", "teardown", "registered", REGISTERED),
            ("teardown.stop", InstanceKind.REGISTERED, REGISTERED),
        ),
        (
            VERB_ARGVS["sweep"],
            ("teardown.sweep", InstanceKind.REGISTERED, REGISTERED, SERVICE),
        ),
        (
            ("internal", "sweep", "auto", AUTO),
            ("teardown.sweep", InstanceKind.AUTO, AUTO, SERVICE),
        ),
        (VERB_ARGVS["key"], ("keyunit.run", REGISTERED)),
        (VERB_ARGVS["key-stop"], ("keyunit.stop_post", REGISTERED, SERVICE)),
    ],
)
def test_each_verb_calls_exactly_its_core_entry_and_exits_0(
    monkeypatch, steamos, ctx, core, fake_runner, argv, expected
):
    for name, value in SERVICE_ENV.items():
        monkeypatch.setenv(name, value)

    assert unit_entry.main(list(argv), ctx=ctx) == 0
    assert core.calls == [expected]
    assert fake_runner.calls == []


def test_sweep_and_key_stop_read_an_unset_service_result_as_none(
    monkeypatch, steamos, ctx, core
):
    for name in SERVICE_ENV:
        monkeypatch.delenv(name, raising=False)

    run_verb("sweep", ctx)
    run_verb("key-stop", ctx)

    nothing = ServiceResult(result=None, exit_code=None, exit_status=None)
    assert [call[-1] for call in core.calls] == [nothing, nothing]


def test_sweep_reads_the_service_result_from_the_environment(
    monkeypatch, steamos, ctx, fake_runner, caplog
):
    for name, value in SERVICE_ENV.items():
        monkeypatch.setenv(name, value)

    assert run_verb("sweep", ctx) == 0

    [entry] = errors_logged(caplog)
    assert entry.getMessage() == (
        f"{REGISTERED}: service result timeout, exit code killed, exit status TERM"
    )
    assert fake_runner.calls == []


def test_teardown_of_an_instance_without_a_record_runs_the_real_routine(
    steamos, ctx, fake_runner, caplog
):
    assert run_verb("teardown", ctx) == 0
    assert errors_logged(caplog) == []
    assert fake_runner.calls == []


@pytest.mark.parametrize(
    ("kind", "path"),
    [
        ("auto", "/sys/devices/host-tree/block/sdb/SDB1"),
        ("auto", "/sys/devices/host-tree/block/sdb/sdb1;reboot"),
        ("auto", "/sys/devices/host-tree/block/sdb/sdb 1"),
        ("auto", "/sys/devices/host-tree/block/sdb/"),
        ("auto", "/sys/devices/../block/sdb"),
        ("auto", "/sys/devices/host-tree/block/sdb/./sdb1"),
        ("auto", "/sys/devices/host-tree/sdb/sdb1"),
        ("auto", "/sys/class/block/sdb1"),
        ("auto", "/dev/sdb1"),
        ("registered", "/dev/sdb1"),
        ("registered", "/dev/disk/by-label/PERSONAL"),
        ("registered", "/dev/disk/by-uuid/../../sda1"),
        ("registered", "/dev/disk/by-uuid/1234"),
        ("registered", f"/dev/disk/by-uuid/{PERSONAL_UUID}/x"),
        ("registered", "/dev/disk/by-uuid/0123456789abcdef\n"),
        ("registered", AUTO),
    ],
)
def test_rejects_bad_kname(steamos, ctx, core, fake_runner, caplog, kind, path):
    code = unit_entry.main(
        ["internal", "reconcile", "--trigger", "start", kind, path], ctx=ctx
    )

    assert code == 0
    assert core.calls == []
    assert fake_runner.calls == []
    [entry] = [record for record in caplog.records if record.levelno >= logging.WARNING]
    assert entry.levelno == logging.WARNING
    assert entry.getMessage().startswith("internal command: device path rejected")


@pytest.mark.parametrize("verb", ["key", "key-stop"])
def test_key_verbs_take_only_a_by_uuid_path(steamos, ctx, core, caplog, verb):
    assert unit_entry.main(["internal", verb, AUTO], ctx=ctx) == 0
    assert core.calls == []
    assert "device path rejected" in caplog.text


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["internal"],
        ["reconcile", "--trigger", "start", "registered", REGISTERED],
        ["internal", "mount", "--volume", "PERSONAL"],
        ["internal", "reconcile", "--trigger", "cli", "registered", REGISTERED],
        ["internal", "reconcile", "registered", REGISTERED],
        ["internal", "reconcile", "--trigger", "start", REGISTERED],
        ["internal", "teardown", "both", REGISTERED],
        ["internal", "sweep", "registered"],
        ["internal", "key"],
        ["internal", "key", REGISTERED, "extra"],
    ],
)
def test_a_malformed_argv_is_logged_and_exits_0(
    steamos, ctx, core, fake_runner, caplog, argv
):
    assert unit_entry.main(argv, ctx=ctx) == 0
    assert core.calls == []
    assert fake_runner.calls == []
    assert "internal command: arguments not understood" in caplog.text


def imported_names(source: str) -> set[str]:
    """``module.name`` for every ``from`` import, ``module`` for every ``import``."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def test_the_import_scan_sees_both_import_forms():
    names = imported_names("import os\nfrom steamos_mounter import cli\n")

    assert names == {"os", "steamos_mounter.cli"}


def test_internal_never_reaches_the_owner_commands_or_waits_on_a_job():
    imported = imported_names(SOURCE.read_text(encoding="utf-8"))
    owner_side = {name for name in imported if ".cli" in name or "commands" in name}
    assert owner_side == set()
    assert "systemd" not in {name.rpartition(".")[2] for name in imported}


def test_a_registered_reconcile_for_an_unplugged_volume_runs_no_command(
    steamos, ctx, fake_runner, caplog
):
    assert run_verb("reconcile", ctx) == 0
    assert fake_runner.calls == []
    assert errors_logged(caplog) == []


# --- the top-level catch --------------------------------------------------------------


@pytest.mark.parametrize("verb", VERBS)
def test_an_exception_in_any_verb_is_logged_with_its_traceback_and_exits_0(
    verb, steamos, ctx, core, caplog
):
    core.error = RuntimeError("injected")

    assert run_verb(verb, ctx) == 0

    [entry] = errors_logged(caplog)
    assert entry.getMessage().startswith(f"internal {verb} of ")
    assert "injected" in entry.getMessage()
    assert entry.exc_info is not None
    assert len(core.calls) == 1


@pytest.mark.parametrize("verb", ["reconcile", "sweep", "key", "key-stop"])
def test_an_internal_error_is_recorded_in_an_existing_registered_record(
    verb, steamos, ctx, core
):
    write_record(steamos, PERSONAL_RECORD, json.dumps(record_dict()).encode())
    (steamos / RUNTIME_TREE / "locks").mkdir(parents=True)
    core.error = RuntimeError("injected")

    run_verb(verb, ctx)

    saved = read_record(steamos, PERSONAL_RECORD)
    assert (saved["state"], saved["reason"], saved["warning"]) == (
        "MountFailed",
        "internal_error",
        None,
    )
    assert saved["next_step"] == (
        f"See the journal, then run {CLI} mount --volume PERSONAL."
    )
    assert saved["mount"] == record_dict()["mount"]


def test_an_internal_error_in_an_auto_teardown_records_the_device_step(
    steamos, ctx, core
):
    auto = record_dict(
        kind="auto",
        key=AUTO_KEY,
        name="GAMES",
        source={"kname": "sdb1", "devnum": "8:17", "syspath": AUTO},
        mapping=None,
    )
    write_record(steamos, AUTO_RECORD, json.dumps(auto).encode())
    core.error = RuntimeError("injected")

    assert run_verb("teardown", ctx) == 0

    saved = read_record(steamos, AUTO_RECORD)
    assert (saved["state"], saved["reason"]) == ("MountFailed", "internal_error")
    assert saved["next_step"] == (
        f"See the journal, then run {CLI} mount --device /dev/sdb1."
    )


@pytest.mark.parametrize("verb", ["reconcile", "teardown"])
def test_an_internal_error_without_a_record_writes_none(verb, steamos, ctx, core):
    core.error = RuntimeError("injected")

    assert run_verb(verb, ctx) == 0

    records_dir = steamos / RUNTIME_TREE / "records"
    assert sorted(path.name for path in records_dir.rglob("*.json")) == []


def test_a_record_that_cannot_be_written_is_logged_and_still_exits_0(
    monkeypatch, steamos, ctx, core, caplog
):
    write_record(steamos, PERSONAL_RECORD, json.dumps(record_dict()).encode())
    before = (steamos / PERSONAL_RECORD).read_bytes()
    core.error = RuntimeError("injected")

    def refuse(*_args: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(records, "update_record", refuse)

    assert run_verb("sweep", ctx) == 0

    messages = [entry.getMessage() for entry in errors_logged(caplog)]
    assert messages[1].startswith(f"the internal error of {REGISTERED} could not")
    assert "No space left on device" in messages[1]
    assert (steamos / PERSONAL_RECORD).read_bytes() == before


@pytest.mark.parametrize("verb", ["teardown", "sweep"])
def test_a_held_volume_lock_is_logged_and_exits_0_without_a_record(
    verb, steamos, ctx, core, caplog
):
    write_record(steamos, PERSONAL_RECORD, json.dumps(record_dict()).encode())
    before = (steamos / PERSONAL_RECORD).read_bytes()
    core.error = LockTimeout("volume busy", detail="volume-x.lock held for 10 s")
    argv = ["internal", verb, "registered", REGISTERED]

    assert unit_entry.main(argv, ctx=ctx) == 0

    [entry] = errors_logged(caplog)
    assert entry.getMessage() == (
        f"internal {verb} of {REGISTERED} not done: volume busy"
        " volume-x.lock held for 10 s"
    )
    assert entry.exc_info is None
    assert (steamos / PERSONAL_RECORD).read_bytes() == before


def test_a_secret_in_an_exception_reaches_the_log_only_redacted(
    steamos, ctx, core, logging_setup
):
    stream = io.StringIO()
    logging_setup("key-unit", journal_socket=str(steamos / "missing"), stderr=stream)
    with SecretBytes(TEST_KEY) as key:
        core.error = RuntimeError(f"cryptsetup echoed {key.reveal().decode()}")

        assert run_verb("key", ctx) == 0

    output = stream.getvalue().encode()
    leaked = TEST_KEY in output
    assert not leaked
    assert b"[REDACTED]" in output
    assert b"Traceback" in output
