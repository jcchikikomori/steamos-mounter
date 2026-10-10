"""``installer.uninstall``: unwire first, then stop, then remove; ``/opt`` last.

Design Doc "Python uninstall (Unwire First, Then Stop)"; ADR-0004 D7, D8
(kept registry, ``--purge``, busy reporting); PRD AC-065. Each test installs a
staged release first (one-file package), then uninstalls it, with real files
under ``tmp_path`` and systemctl and udevadm on the fake runner.
"""

import json
import os
import shutil
from pathlib import Path

import pytest

from steamos_mounter import installer
from steamos_mounter.errors import ExitCode
from steamos_mounter.installer_report import StepLine
from tests.helpers.builders import record_dict
from tests.helpers.cli_env import (
    MEDIABOX_LINK,
    MEDIABOX_RECORD,
    MEDIABOX_REGISTRY,
    MEDIABOX_UNIT,
    MEDIABOX_UUID,
    run_cli,
)
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import SETFACL, write_key_file, write_record, write_registry
from tests.helpers.installer_env import (
    DAEMON_RELOAD,
    ETC_FILES,
    INSTANCES,
    KEPT_REGISTRY,
    KEY_UNITS,
    KEYS_DIR,
    OPT,
    REGISTRY,
    RUN_TREE,
    UDEVADM_RELOAD,
    pinned_umask,
    release_ctx,
    stage_release,
    system_tree,
    units_answer,
)

SYSTEMCTL = DAEMON_RELOAD[0]
KEY_UNIT = MEDIABOX_UNIT.replace("steamos-mounter@", "steamos-mounter-key@")
AUTO_UNIT = "steamos-mounter-auto@sys-devices-host\\x2dtree-block-sdc1.service"
STOP_KEY = (SYSTEMCTL, "stop", "--", KEY_UNIT)
STOP_INSTANCES = (SYSTEMCTL, "stop", "--", MEDIABOX_UNIT, AUTO_UNIT)
MEDIABOX_KEY = f"{KEYS_DIR}/{MEDIABOX_UUID}.key"
BUSY_DETAIL = (
    "/run/media/deck/MEDIABOX still busy: finishes when the last open file is closed"
)


@pytest.fixture(autouse=True)
def umask_022():
    with pinned_umask():
        yield


@pytest.fixture
def installed(ctx, tmp_path: Path, fake_runner):
    """An installed host with MEDIABOX registered and its key stored."""
    system_tree(tmp_path)
    write_registry(tmp_path, MEDIABOX_REGISTRY)
    write_key_file(tmp_path, MEDIABOX_UUID, b"TEST-KEY")
    release = stage_release(tmp_path, package=False)
    rctx = release_ctx(ctx, release)
    fake_runner.on(DAEMON_RELOAD, Answer())
    fake_runner.on(UDEVADM_RELOAD, Answer())
    fake_runner.on(SETFACL, Answer())
    report = installer.install(rctx, release=release, start_present=False)
    assert report.exit_code == ExitCode.OK
    fake_runner.calls.clear()
    return rctx


def script_uninstall(
    runner,
    *,
    stop_rc: int = 0,
    udev_rc: int = 0,
    key_stop_rc: int = 0,
    daemon_reloads: tuple[Answer, ...] = (Answer(), Answer()),
    on_udev=None,
    on_daemon_reload=None,
    on_stop=None,
    on_instances_stop=None,
) -> None:
    runner.on(UDEVADM_RELOAD, Answer(returncode=udev_rc), hook=on_udev)
    runner.on(DAEMON_RELOAD, *daemon_reloads, hook=on_daemon_reload)
    runner.on(KEY_UNITS, units_answer(KEY_UNIT))
    runner.on(STOP_KEY, Answer(returncode=key_stop_rc), hook=on_stop)
    runner.on(INSTANCES, units_answer(MEDIABOX_UNIT, AUTO_UNIT))
    runner.on(STOP_INSTANCES, Answer(returncode=stop_rc), hook=on_instances_stop)


def lines_of(report) -> dict[str, StepLine]:
    return {line.step: line for line in report.lines}


def test_uninstall_order_and_kept_registry(installed, tmp_path, fake_runner):
    os.umask(0o002)  # the caller's; the umask_022 fixture restores it at teardown
    registry = (tmp_path / REGISTRY).read_bytes()
    gone: list[bool] = []
    masks: list[int] = []
    reloads: list[tuple[bool, bool]] = []
    units = [tmp_path / path for path in ETC_FILES[:4]]  # drop-in and templates

    def at_udev_reload() -> None:
        gone.append(not (tmp_path / ETC_FILES[4]).exists())
        mask = os.umask(0o002)  # read it, then set it back
        os.umask(mask)
        masks.append(mask)

    def at_daemon_reload(_cmd) -> None:
        link = os.path.lexists(tmp_path / MEDIABOX_LINK)
        reloads.append((link, any(os.path.lexists(path) for path in units)))

    script_uninstall(
        fake_runner,
        on_udev=lambda _cmd: at_udev_reload(),
        on_daemon_reload=at_daemon_reload,
    )

    report = installer.uninstall(installed, purge=False)

    assert report.exit_code == ExitCode.OK
    assert fake_runner.argvs == [
        UDEVADM_RELOAD,
        DAEMON_RELOAD,
        KEY_UNITS,
        STOP_KEY,
        INSTANCES,
        STOP_INSTANCES,
        DAEMON_RELOAD,
    ]
    assert gone == [True]
    assert masks == [0o022]  # the installer's own umask, mid-run
    # First reload: the link is gone, the units still there. Second: units gone.
    assert reloads == [(False, True), (False, False)]
    assert not any(os.path.lexists(tmp_path / path) for path in ETC_FILES)
    assert not os.path.lexists(tmp_path / MEDIABOX_LINK)
    assert not (tmp_path / "etc/steamos-mounter").exists()
    assert not (tmp_path / RUN_TREE).exists()
    assert not (tmp_path / OPT).exists()
    assert (tmp_path / KEPT_REGISTRY).read_bytes() == registry
    assert (tmp_path / MEDIABOX_KEY).read_bytes() == b"TEST-KEY"
    assert lines_of(report)["registry"] == StepLine(
        "registry",
        "ok",
        "kept at /var/lib/steamos-mounter/kept-config.toml; keys kept",
    )
    assert report.lines[-1] == StepLine("remove /opt/steamos-mounter", "ok", "")


def test_links_are_gone_before_the_first_stop(installed, tmp_path, fake_runner):
    wired: list[bool] = []
    script_uninstall(
        fake_runner,
        on_stop=lambda _cmd: wired.append(os.path.lexists(tmp_path / MEDIABOX_LINK)),
    )

    installer.uninstall(installed, purge=False)

    assert wired == [False]


def test_purge_deletes_the_registry_and_the_keys(installed, tmp_path, fake_runner):
    script_uninstall(fake_runner)

    report = installer.uninstall(installed, purge=True)

    assert report.exit_code == ExitCode.OK
    assert not (tmp_path / REGISTRY).exists()
    assert not (tmp_path / "var/lib/steamos-mounter").exists()
    assert sorted(os.listdir(tmp_path / "etc")) == [
        "atomic-update.conf.d",
        "os-release",
        "systemd",
        "udev",
    ]
    assert lines_of(report)["registry"].detail == "registry and keys deleted"


def test_without_a_registry_there_is_nothing_to_keep(installed, tmp_path, fake_runner):
    (tmp_path / REGISTRY).unlink()
    script_uninstall(fake_runner)

    report = installer.uninstall(installed, purge=False)

    assert lines_of(report)["registry"] == StepLine(
        "registry", "skipped", "no registry"
    )
    assert not (tmp_path / KEPT_REGISTRY).exists()


def test_busy_items_are_reported_last_with_exit_6(installed, tmp_path, fake_runner):
    def teardown(_cmd) -> None:
        """MEDIABOX's ExecStop needed a lazy unmount while stop blocked."""
        record = record_dict(
            key=MEDIABOX_UUID.lower(),
            name="MEDIABOX",
            busy=["/run/media/deck/MEDIABOX"],
            mapping=None,
        )
        write_record(tmp_path, MEDIABOX_RECORD, json.dumps(record).encode())

    write_record(tmp_path, "run/steamos-mounter/records/auto/notes.txt", b"x")
    write_record(tmp_path, "run/steamos-mounter/records/auto/Bad Key.json", b"{}")
    write_record(tmp_path, "run/steamos-mounter/records/auto/sdz9-8_1.json", b"{")
    script_uninstall(fake_runner, on_instances_stop=teardown)

    report = installer.uninstall(installed, purge=False)

    assert report.exit_code == ExitCode.BUSY
    assert report.lines[-1] == StepLine("MEDIABOX", "busy", BUSY_DETAIL)
    assert not (tmp_path / OPT).exists()


@pytest.mark.parametrize(
    ("failure", "last_step", "stops"),
    [
        ("udevadm", "udevadm reload", []),
        ("unwire", "unwire", []),
        ("daemon-reload", "daemon-reload", []),
        ("key-stop", "stop key units", [STOP_KEY]),
    ],
)
def test_a_failure_before_the_instances_stop_stops_nothing_more(
    installed, tmp_path, fake_runner, request, failure, last_step, stops
):
    if failure == "unwire":
        assert os.geteuid() != 0, "root ignores the read-only dir: run as non-root"
        # The link cannot be removed: its .device.wants dir is read-only.
        wants = (tmp_path / MEDIABOX_LINK).parent
        wants.chmod(0o555)
        request.addfinalizer(lambda: wants.chmod(0o755))
    script_uninstall(
        fake_runner,
        udev_rc=1 if failure == "udevadm" else 0,
        daemon_reloads=(Answer(returncode=1 if failure == "daemon-reload" else 0),),
        key_stop_rc=1 if failure == "key-stop" else 0,
    )

    report = installer.uninstall(installed, purge=False)

    assert report.exit_code == ExitCode.PARTIAL
    assert report.lines[-1].step == last_step
    assert report.lines[-1].status == "failed"
    assert [argv for argv in fake_runner.argvs if argv[1:2] == ("stop",)] == stops
    assert (tmp_path / OPT).exists()
    assert (tmp_path / ETC_FILES[0]).exists()  # the drop-in
    assert (tmp_path / REGISTRY).exists()


def test_a_failed_stop_removes_nothing_more(installed, tmp_path, fake_runner):
    script_uninstall(fake_runner, stop_rc=1)

    report = installer.uninstall(installed, purge=False)

    assert report.exit_code == ExitCode.PARTIAL
    assert report.lines[-1] == StepLine(
        "stop instances", "failed", "the instances did not stop: run uninstall again"
    )
    assert (tmp_path / ETC_FILES[1]).exists()
    assert (tmp_path / REGISTRY).exists()
    assert (tmp_path / OPT).exists()


def test_a_later_failure_keeps_opt_for_the_next_run(installed, tmp_path, fake_runner):
    script_uninstall(fake_runner, daemon_reloads=(Answer(), Answer(returncode=1)))

    report = installer.uninstall(installed, purge=False)

    assert report.exit_code == ExitCode.PARTIAL
    assert lines_of(report)["remove /opt/steamos-mounter"] == StepLine(
        "remove /opt/steamos-mounter",
        "skipped",
        "an earlier step failed: run uninstall again",
    )
    assert report.lines[-1].step == "daemon-reload"
    assert (tmp_path / OPT).exists()


def test_no_units_loaded_skips_the_stops(installed, tmp_path, fake_runner):
    fake_runner.on(UDEVADM_RELOAD, Answer())
    fake_runner.on(DAEMON_RELOAD, Answer(), Answer())
    fake_runner.on(KEY_UNITS, Answer())
    fake_runner.on(INSTANCES, Answer())
    (tmp_path / MEDIABOX_LINK).unlink()
    (tmp_path / ETC_FILES[4]).unlink()

    report = installer.uninstall(installed, purge=False)

    assert report.exit_code == ExitCode.OK
    assert lines_of(report)["stop key units"].status == "skipped"
    assert lines_of(report)["stop instances"].status == "skipped"
    assert lines_of(report)["unwire"].status == "skipped"
    assert lines_of(report)[f"remove /{ETC_FILES[4]}"].status == "skipped"


def test_a_registry_dir_with_other_files_is_left(installed, tmp_path, fake_runner):
    (tmp_path / "etc/steamos-mounter/notes").write_text("x", encoding="utf-8")
    script_uninstall(fake_runner)

    report = installer.uninstall(installed, purge=False)

    assert lines_of(report)["remove /etc/steamos-mounter"] == StepLine(
        "remove /etc/steamos-mounter", "skipped", "not empty: left in place"
    )
    assert report.exit_code == ExitCode.OK


def test_nothing_installed_is_nothing_to_remove(ctx, tmp_path, fake_runner):
    system_tree(tmp_path)

    report = installer.uninstall(ctx, purge=False)

    assert report.exit_code == ExitCode.OK
    assert report.lines == (StepLine("check", "skipped", "nothing to remove"),)
    assert fake_runner.calls == []


def test_an_unreadable_installed_manifest_exits_5(ctx, tmp_path, fake_runner):
    system_tree(tmp_path)
    (tmp_path / OPT).mkdir()

    report = installer.uninstall(ctx, purge=False)

    assert report.exit_code == ExitCode.PARTIAL
    assert report.lines == (
        StepLine("manifest", "failed", "the install manifest is unusable"),
    )
    assert fake_runner.calls == []


def test_guards_come_first(ctx_deck, tmp_path, fake_runner):
    system_tree(tmp_path)
    (tmp_path / OPT).mkdir()

    report = installer.uninstall(ctx_deck, purge=True)

    assert report.exit_code == ExitCode.NEEDS_ROOT
    assert (tmp_path / OPT).exists()


def test_the_uninstall_command_prints_prefixed_lines(installed, fake_runner):
    script_uninstall(fake_runner)

    result = run_cli(installed, "uninstall")

    assert result.code == ExitCode.OK
    lines = result.out.splitlines()
    assert lines[0] == "steamos-mounter uninstall: manifest: ok"
    assert all(line.startswith("steamos-mounter uninstall: ") for line in lines)


def test_purge_after_a_reboot_finds_little_to_remove(installed, tmp_path, fake_runner):
    # /run is tmpfs: its tree is gone; /etc/steamos-mounter went with a hand clean-up.
    shutil.rmtree(tmp_path / RUN_TREE)
    shutil.rmtree(tmp_path / "etc/steamos-mounter")
    script_uninstall(fake_runner)

    report = installer.uninstall(installed, purge=True)

    assert report.exit_code == ExitCode.OK
    assert lines_of(report)["remove /run/steamos-mounter"].status == "skipped"
    assert lines_of(report)["remove /etc/steamos-mounter"].status == "skipped"
    assert not (tmp_path / OPT).exists()


def test_a_file_in_place_of_the_registry_dir_is_a_failed_step(
    installed, tmp_path, fake_runner
):
    shutil.rmtree(tmp_path / "etc/steamos-mounter")
    (tmp_path / "etc/steamos-mounter").write_text("x", encoding="utf-8")
    script_uninstall(fake_runner)

    report = installer.uninstall(installed, purge=False)

    failed = [line.step for line in report.lines if line.status == "failed"]
    assert report.exit_code == ExitCode.PARTIAL
    assert "remove /etc/steamos-mounter" in failed
    assert (tmp_path / OPT).exists()
