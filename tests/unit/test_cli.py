"""cli: the owner parser, the guards, dispatch and the one-line error.

Design Doc "CLI Contract > Global Rules" (guard order, plain output, one
generic error line, NOTICE per command, keys never options), DD-03, DD-30,
AC-012, AC-042 and AC-066 ("Required Specific Tests: Root guard": each
root-only command as uid 1000 exits 3 with an empty fake-runner call log, so
no ``systemctl`` and no polkit prompt). The host tree is real files under
``tmp_path``; external commands go through the fake runner.
"""

import argparse
import logging

import pytest

from steamos_mounter import __version__, blockdev, cli, unit_entry
from steamos_mounter.errors import ExitCode, MounterError, UnsupportedPlatformError
from steamos_mounter.journal import NOTICE
from tests.helpers.cli_env import (
    CLI,
    DETAILS,
    MEDIABOX_REGISTRY,
    MEDIABOX_UNIT,
    files_under,
    given_host,
    run_cli,
    script_table,
    script_tree,
    script_unit,
    steamos_host,
    verb_argv,
)
from tests.helpers.flows import sm_fields

TEST_KEY = "TEST-KEY-7f3a9c-do-not-leak"
ROOT_ONLY_ARGVS = {
    "add": ("add", "--device", "/dev/sdb5"),
    "remove": ("remove", "MEDIABOX"),
    "mount": ("mount", "--volume", "MEDIABOX"),
    "unmount": ("unmount", "--volume", "MEDIABOX"),
}
IMPLEMENTED = ("add", "remove", "mount", "unmount")


def option_strings(parser: argparse.ArgumentParser) -> set[str]:
    return {name for action in parser._actions for name in action.option_strings}


def subparser(name: str) -> argparse.ArgumentParser:
    parser = cli.build_parser([])
    choices = next(
        action.choices
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    return choices[name]


# --- AC-012: keys are never options ---------------------------------------------------


def test_no_key_option_exists():
    for name in IMPLEMENTED:
        names = option_strings(subparser(name))
        keyish = {option for option in names if "key" in option or "pass" in option}
        assert keyish <= {"--key-file", "--key-stdin"}
    assert {"--key-file", "--key-stdin"} <= option_strings(subparser("add"))


@pytest.mark.parametrize(
    "argv",
    [
        ("add", "--device", "/dev/sdb1", "--key", TEST_KEY),
        ("add", "--device", "/dev/sdb1", f"--key={TEST_KEY}"),
        ("add", "--device", "/dev/sdb1", "--password", TEST_KEY),
        ("add", "--device", "/dev/sdb1", "--key-f", TEST_KEY),  # no abbreviations
        ("add", "--device", "/dev/sdb1", TEST_KEY),
    ],
    ids=["key", "key-equals", "password", "abbreviated", "positional"],
)
def test_a_key_given_as_an_argument_is_refused_and_never_echoed(
    ctx, tmp_path, fake_runner, argv
):
    steamos_host(tmp_path)

    result = run_cli(ctx, *argv)

    assert result.code == ExitCode.USAGE
    assert TEST_KEY not in result.out + result.err
    assert result.err.count("\n") == 1
    assert fake_runner.calls == []


# --- --help, --version, internal -----------------------------------------------------


def test_help_lists_the_commands_and_no_internal(ctx_deck, tmp_path):
    result = run_cli(ctx_deck, "--help")

    assert result.code == ExitCode.OK
    assert result.err == ""
    assert "internal" not in result.out
    for name in IMPLEMENTED:
        assert f"    {name} " in result.out


def test_help_is_exempt_from_the_guards(ctx_deck, tmp_path, fake_runner):
    steamos_host(tmp_path, os_id="debian")

    top = run_cli(ctx_deck, "--help")
    sub = run_cli(ctx_deck, "add", "--help")

    assert (top.code, sub.code) == (ExitCode.OK, ExitCode.OK)
    assert "--key-file FILE" in sub.out
    assert fake_runner.calls == []
    assert files_under(tmp_path) == ["etc", "etc/os-release", "run"]


def test_help_stays_plain_when_color_is_forced(ctx_deck, monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)

    result = run_cli(ctx_deck, "add", "--help")

    assert "\x1b" not in result.out
    assert "[1m" not in result.out
    assert "usage: steamos-mounter add" in result.out


def test_version_prints_the_package_version(ctx_deck, tmp_path):
    steamos_host(tmp_path, os_id="debian")

    result = run_cli(ctx_deck, "--version")

    assert (result.code, result.out, result.err) == (
        ExitCode.OK,
        f"steamos-mounter {__version__}\n",
        "",
    )


def test_internal_goes_to_unit_entry_untouched(ctx, monkeypatch):
    calls = []

    def recorded(argv, *, ctx=None):
        calls.append((list(argv), ctx))
        return 0

    monkeypatch.setattr(unit_entry, "main", recorded)
    argv = ["internal", "teardown", "auto", "/sys/devices/x/block/sdb/sdb1"]

    assert cli.main(argv, ctx=ctx) == 0
    assert calls == [(argv, ctx)]


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        ((), "a command is required. Run steamos-mounter --help."),
        (("frobnicate",), "invalid choice"),
        (("mount",), "one of the arguments --volume --device is required"),
        (("add", "--device", "/dev/a", "--uuid", "X"), "not allowed with argument"),
    ],
    ids=["none", "unknown", "missing", "exclusive"],
)
def test_usage_errors_exit_2_with_one_line(ctx, tmp_path, fake_runner, argv, message):
    steamos_host(tmp_path)

    result = run_cli(ctx, *argv)

    assert result.code == ExitCode.USAGE
    assert result.out == ""
    assert result.err.startswith("steamos-mounter: ")
    assert message in result.err
    assert result.err.count("\n") == 1
    assert fake_runner.calls == []


# --- guards (DD-30, AC-066) -----------------------------------------------------------


@pytest.mark.parametrize("command", sorted(ROOT_ONLY_ARGVS))
def test_root_only_without_root_no_calls(ctx_deck, tmp_path, fake_runner, command):
    steamos_host(tmp_path)
    before = files_under(tmp_path)

    result = run_cli(ctx_deck, *ROOT_ONLY_ARGVS[command])

    assert result.code == ExitCode.NEEDS_ROOT
    assert result.err == f"steamos-mounter: {command} needs root: run it with sudo.\n"
    assert result.out == ""
    assert fake_runner.calls == []
    assert files_under(tmp_path) == before


@pytest.mark.parametrize("command", sorted(ROOT_ONLY_ARGVS))
@pytest.mark.parametrize("as_root", [True, False], ids=["root", "deck"])
def test_non_steamos_exits_4_before_the_root_check(
    ctx, ctx_deck, tmp_path, fake_runner, command, as_root
):
    steamos_host(tmp_path, os_id="debian")
    before = files_under(tmp_path)

    result = run_cli(ctx if as_root else ctx_deck, *ROOT_ONLY_ARGVS[command])

    assert result.code == ExitCode.UNSUPPORTED_PLATFORM
    assert result.err == "steamos-mounter: unsupported platform: SteamOS only.\n"
    assert fake_runner.calls == []
    assert files_under(tmp_path) == before


def test_a_usage_error_off_steamos_still_reports_the_platform(ctx_deck, tmp_path):
    steamos_host(tmp_path, os_id="debian")

    result = run_cli(ctx_deck, "add", "--bogus")

    assert result.code == ExitCode.UNSUPPORTED_PLATFORM


def test_a_usage_error_comes_before_the_root_check(ctx_deck, tmp_path, fake_runner):
    steamos_host(tmp_path)

    result = run_cli(ctx_deck, "add", "--device", "/dev/sdb5", "--bogus")

    assert result.code == ExitCode.USAGE
    assert result.err == (
        "steamos-mounter: unrecognized arguments. Run steamos-mounter --help.\n"
    )


def test_a_root_run_recreates_the_runtime_tree_first(ctx, tmp_path, fake_runner):
    steamos_host(tmp_path)
    fake_runner.on(blockdev.LSBLK_COLUMNS, lambda: None)  # never matched
    script_tree(fake_runner)
    script_table(fake_runner)

    result = run_cli(ctx, "mount", "--volume", "MEDIABOX")

    # No /etc/steamos-mounter: the registry is unusable, but the tree is back.
    assert result.code == ExitCode.FAILED
    assert (tmp_path / "run/steamos-mounter/locks").is_dir()


# --- AC-042: one generic line ---------------------------------------------------------


def failing_lsblk(fake_runner) -> None:
    from tests.helpers.fake_runner import Answer
    from tests.helpers.flows import LSBLK_ARGV

    fake_runner.on(LSBLK_ARGV, Answer(returncode=1, stderr=b"lsblk: secret detail\n"))


def test_error_is_one_generic_line(ctx, tmp_path, fake_runner, caplog):
    given_host(ctx, tmp_path, registry=MEDIABOX_REGISTRY)
    failing_lsblk(fake_runner)

    with caplog.at_level(logging.DEBUG):
        result = run_cli(ctx, "mount", "--volume", "MEDIABOX")

    assert result.code == ExitCode.FAILED
    assert result.out == ""
    assert result.err == f"steamos-mounter: cannot list block devices. {DETAILS}\n"
    assert "secret detail" in caplog.text  # the detail went to the journal only


def test_an_unexpected_exception_is_one_line_and_logged_with_its_traceback(
    ctx, tmp_path, fake_runner, caplog, monkeypatch
):
    given_host(ctx, tmp_path, registry=MEDIABOX_REGISTRY)

    def broken(_ctx):
        raise RuntimeError("boom with internal words")

    monkeypatch.setattr(blockdev, "read_tree", broken)

    with caplog.at_level(logging.DEBUG):
        result = run_cli(ctx, "mount", "--volume", "MEDIABOX")

    assert result.code == ExitCode.FAILED
    assert result.err == (
        "steamos-mounter: internal error. Run it again; if it fails again, see the"
        f" journal. {DETAILS}\n"
    )
    assert "boom" not in result.err
    assert "Traceback" not in result.err
    errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert errors[-1].exc_info is not None


def test_a_message_that_ends_with_a_period_gets_no_second_one():
    assert cli._line("done.") == f"done. {DETAILS}"
    assert cli._line("done") == f"done. {DETAILS}"


# --- NOTICE per command ---------------------------------------------------------------


def test_every_command_logs_its_start_and_outcome_at_notice(
    ctx, tmp_path, fake_runner, caplog
):
    given_host(ctx, tmp_path, registry=MEDIABOX_REGISTRY)
    script_tree(fake_runner)
    script_table(fake_runner)

    with caplog.at_level(logging.DEBUG):
        result = run_cli(ctx, "remove", "NOPE")

    assert result.code == ExitCode.USAGE
    events = [
        (record.levelno, record.getMessage())
        for record in caplog.records
        if sm_fields(record).get("SM_EVENT") == "remove"
    ]
    assert events[0] == (NOTICE, "remove started")
    assert events[-1][0] >= NOTICE
    assert "no registered volume is called NOPE" in events[-1][1]


def test_a_successful_command_logs_its_outcome_at_notice(
    ctx, tmp_path, fake_runner, caplog
):
    given_host(ctx, tmp_path, registry=MEDIABOX_REGISTRY)
    script_tree(fake_runner)
    script_table(fake_runner)
    script_unit(fake_runner, MEDIABOX_UNIT, "active")
    fake_runner.on(verb_argv("reload", MEDIABOX_UNIT, block=True), "findmnt-sda1.json")

    with caplog.at_level(logging.DEBUG):
        run_cli(ctx, "mount", "--volume", "MEDIABOX")

    outcome = [
        record
        for record in caplog.records
        if sm_fields(record).get("SM_EVENT") == "mount"
        and "finished" in record.getMessage()
    ]
    assert len(outcome) == 1
    assert outcome[0].levelno >= NOTICE


# --- the real entry (no injected context) ---------------------------------------------


@pytest.fixture
def host_facts(monkeypatch):
    """The ``ctx=None`` path: the platform and euid as ``unit_entry`` reads them."""

    def set_facts(*, steamos: bool, euid: int) -> None:
        def platform():
            if not steamos:
                raise UnsupportedPlatformError("unsupported platform")

        monkeypatch.setattr(unit_entry, "current_platform", platform)
        monkeypatch.setattr(unit_entry.os, "geteuid", lambda: euid)

    return set_facts


def test_without_a_context_off_steamos_exits_4(host_facts, monkeypatch):
    host_facts(steamos=False, euid=0)
    monkeypatch.setattr(cli, "build_context", pytest.fail)

    assert cli.main(["mount", "--volume", "X"]) == ExitCode.UNSUPPORTED_PLATFORM


def test_without_a_context_as_deck_exits_3(host_facts, monkeypatch):
    host_facts(steamos=True, euid=1000)
    monkeypatch.setattr(cli, "build_context", pytest.fail)

    assert cli.main(["unmount", "--volume", "X"]) == ExitCode.NEEDS_ROOT


def test_without_a_context_the_cli_builds_one_with_the_release(
    host_facts, monkeypatch, ctx, tmp_path, fake_runner
):
    host_facts(steamos=True, euid=0)
    given_host(ctx, tmp_path, registry=MEDIABOX_REGISTRY)
    built = []

    def build(**kwargs):
        built.append(kwargs)
        return ctx

    monkeypatch.setattr(cli, "build_context", build)

    code = cli.main(
        ["remove", "NOPE"], release_root="/opt/steamos-mounter/releases/0.1.0"
    )

    assert code == ExitCode.USAGE
    assert built == [
        {"component": "cli", "release_root": "/opt/steamos-mounter/releases/0.1.0"}
    ]


def test_an_untrusted_runtime_tree_exits_1_with_one_line(
    host_facts, monkeypatch, capsys
):
    host_facts(steamos=True, euid=0)

    def build(**_kwargs):
        raise MounterError("the runtime state directory cannot be trusted: run doctor")

    monkeypatch.setattr(cli, "build_context", build)

    code = cli.main(["mount", "--volume", "X"])

    assert code == ExitCode.FAILED
    captured = capsys.readouterr()
    assert captured.err == (
        "steamos-mounter: the runtime state directory cannot be trusted: run"
        f" doctor. {DETAILS}\n"
    )


def test_argv_defaults_to_the_process_arguments(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["steamos-mounter", "--version"])

    assert cli.main() == ExitCode.OK
    assert capsys.readouterr().out == f"steamos-mounter {__version__}\n"


def test_the_cli_root_hint_is_the_absolute_sudo_path(fake_platform):
    assert fake_platform.cli_root == CLI
