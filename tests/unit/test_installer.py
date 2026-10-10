"""``installer.install``: install equals update, the release checks, every step.

Design Doc "Python install (Install Equals Update)", "Install Manifest
(Authoritative)" and "Installer Contract for the Future Dotfiles Wrapper";
ADR-0004 D1, D7, D8.6, D11; PRD AC-037, AC-039; work plan decision item 2
(``ctx.release_root``). Real files under ``tmp_path`` with the test uid as
the trusted owner; systemctl, udevadm, setfacl and lsblk on the fake runner.
The staged release carries a one-file package (``package=False``) so each
compile is instant; the integration tests stage the real package.
"""

import dataclasses
import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from steamos_mounter import installer, installer_report
from steamos_mounter.errors import ExitCode, MounterError
from steamos_mounter.installer_report import StepLine, render
from steamos_mounter.manifest import Entry
from tests.helpers.cli_env import (
    BROKEN_REGISTRY,
    MEDIABOX_LINK,
    MEDIABOX_REGISTRY,
    MEDIABOX_UNIT,
    MEDIABOX_UUID,
    partition,
    run_cli,
    script_tree,
    script_unit,
    tree_with,
    verb_argv,
)
from tests.helpers.fake_platform import FakePlatform
from tests.helpers.fake_runner import Answer
from tests.helpers.flows import (
    LSBLK_ARGV,
    SETFACL,
    known_os_set,
    write_key_file,
    write_registry,
)
from tests.helpers.host_tree import SysfsDevice
from tests.helpers.installer_env import (
    BIN_LINK,
    CURRENT,
    DAEMON_RELOAD,
    ETC_FILES,
    KEPT_REGISTRY,
    KEYS_DIR,
    REGISTRY,
    RELEASE_NAME,
    RELEASES,
    RUN_TREE,
    UDEVADM_RELOAD,
    mode_of,
    pinned_umask,
    release_ctx,
    script_reloads,
    snapshot,
    stage_release,
    system_tree,
)

TEMPLATE = "/etc/systemd/system/steamos-mounter@.service"
MEDIABOX_KEY = f"{KEYS_DIR}/{MEDIABOX_UUID}.key"
GAMES_UNIT = "steamos-mounter-auto@sys-devices-host\\x2dtree-block-sdc1.service"
WRITE_STEPS = tuple(f"write /{path}" for path in ETC_FILES)


@pytest.fixture
def host(tmp_path: Path) -> Iterator[Path]:
    with pinned_umask():
        system_tree(tmp_path)
        yield tmp_path


@pytest.fixture
def release(host: Path) -> Path:
    return stage_release(host, package=False)


@pytest.fixture
def rctx(ctx, release):
    return release_ctx(ctx, release)


@pytest.fixture
def reloads(fake_runner):
    script_reloads(fake_runner)
    return fake_runner


def install(rctx, release, **kwargs):
    kwargs.setdefault("start_present", False)
    return installer.install(rctx, release=release, **kwargs)


def lines_of(report) -> dict[str, StepLine]:
    return {line.step: line for line in report.lines}


def statuses(report) -> dict[str, str]:
    return {line.step: line.status for line in report.lines}


# --- AC-037: install twice, same tree -------------------------------------------------


def test_install_twice_same_tree(rctx, release, host, reloads):
    write_registry(host, MEDIABOX_REGISTRY)
    key = write_key_file(host, MEDIABOX_UUID, b"TEST-KEY")
    registry = host / REGISTRY
    kept = {path: (path.read_bytes(), os.stat(path)) for path in (registry, key)}

    first = install(rctx, release)
    tree = snapshot(host)
    second = install(rctx, release)

    assert first.exit_code == ExitCode.OK
    assert {line.status for line in first.lines} <= {"ok", "skipped"}
    assert os.readlink(host / CURRENT) == f"releases/{RELEASE_NAME}"
    assert os.readlink(host / BIN_LINK) == "current/bin"
    for path in ETC_FILES:
        assert mode_of(host / path) == 0o644
        source = release / "data" / Path(path).name
        assert (host / path).read_bytes() == source.read_bytes()
    assert os.readlink(host / MEDIABOX_LINK) == TEMPLATE
    assert second.exit_code == ExitCode.OK
    assert snapshot(host) == tree
    assert {step: statuses(second)[step] for step in WRITE_STEPS} == dict.fromkeys(
        WRITE_STEPS, "skipped"
    )
    assert statuses(second)["current"] == "skipped"
    assert statuses(second)["wiring"] == "skipped"
    for path, (data, before) in kept.items():
        after = os.stat(path)
        assert path.read_bytes() == data
        assert (after.st_mode, after.st_mtime_ns) == (
            before.st_mode,
            before.st_mtime_ns,
        )


def test_install_creates_the_manifest_directories_with_their_modes(
    rctx, release, host, reloads
):
    report = install(rctx, release)

    assert report.exit_code == ExitCode.OK
    assert mode_of(host / "etc/steamos-mounter") == 0o755
    assert mode_of(host / "var/lib/steamos-mounter") == 0o755
    assert mode_of(host / KEYS_DIR) == 0o700
    assert [mode_of(host / RUN_TREE / sub) for sub in ("", "records", "locks")] == [
        0o755,
        0o755,
        0o700,
    ]
    assert not (host / REGISTRY).exists()  # never created by the installer (I001)


def test_install_fixes_the_mode_of_an_existing_directory(rctx, release, host, reloads):
    keys = host / KEYS_DIR
    keys.mkdir(parents=True)
    keys.chmod(0o755)

    report = install(rctx, release)

    assert mode_of(keys) == 0o700
    assert lines_of(report)["directories"].status == "ok"


def test_a_symlink_in_place_of_a_directory_is_a_failed_step(
    rctx, release, host, reloads
):
    (host / "elsewhere").mkdir()
    (host / "etc/steamos-mounter").symlink_to(host / "elsewhere")

    report = install(rctx, release)

    failed = [line.step for line in report.lines if line.status == "failed"]
    assert report.exit_code == ExitCode.PARTIAL
    assert failed == ["directories", "wiring"]  # the registry dir is untrusted too
    assert [line.status for line in report.lines[-2:]] == ["failed", "failed"]
    assert (host / "etc/steamos-mounter").is_symlink()


# --- AC-039: the release must be root-owned and read-only -----------------------------


@pytest.mark.parametrize(
    "spoil",
    ["group-writable-file", "other-writable-dir", "symlink", "releases-writable"],
)
def test_rejects_writable_release(rctx, release, host, fake_runner, spoil):
    if spoil == "group-writable-file":
        (release / "lib/steamos_mounter/__init__.py").chmod(0o664)
    elif spoil == "other-writable-dir":
        (release / "data").chmod(0o757)
    elif spoil == "symlink":
        (release / "lib/steamos_mounter/cli.py").symlink_to("__init__.py")
    else:
        (host / RELEASES).chmod(0o775)
    before = snapshot(host)

    report = install(rctx, release)

    assert report.exit_code == ExitCode.PARTIAL
    assert report.lines == (
        StepLine(
            "release",
            "failed",
            "the release is not a root-owned, read-only tree: run install.sh",
        ),
    )
    assert snapshot(host) == before
    assert fake_runner.calls == []


def test_rejects_a_release_owned_by_another_uid(rctx, release, host, fake_runner):
    foreign = dataclasses.replace(
        rctx, platform=FakePlatform(trusted_uid=os.getuid() + 1)
    )

    report = install(foreign, release)

    assert report.exit_code == ExitCode.PARTIAL
    assert [line.step for line in report.lines] == ["release"]
    assert fake_runner.calls == []


def test_tree_problem_names_the_foreign_owner(release):
    problem = installer.tree_problem(release, os.getuid() + 1)

    assert problem == f"{release} is owned by uid {os.getuid()}"


def test_an_unreadable_release_directory_fails_closed(rctx, release, host, request):
    hidden = release / "data"
    hidden.chmod(0o300)
    request.addfinalizer(lambda: hidden.chmod(0o755))

    assert os.geteuid() != 0
    assert installer.tree_problem(release, os.getuid()).endswith(
        "cannot be checked: Permission denied"
    )


@pytest.mark.parametrize(
    ("given", "message"),
    [
        ("elsewhere", "--release is not a release directory under"),
        ("relative", "--release is not a release directory under"),
        ("other", "--release is not the release this installer runs from"),
        ("unknown", "the running release is unknown: run install.sh"),
    ],
)
def test_a_release_mismatch_exits_5_before_any_write(
    ctx, release, host, fake_runner, given, message
):
    other = stage_release(host, "0.1.0-20261009T000000Z", package=False)
    paths = {
        "elsewhere": host / "tmp-release",
        "relative": Path(f"{RELEASES}/{RELEASE_NAME}"),
        "other": other,
        "unknown": release,
    }
    running = None if given == "unknown" else release
    before = snapshot(host)

    report = install(release_ctx(ctx, running), paths[given])

    assert report.exit_code == ExitCode.PARTIAL
    assert report.lines[-1].detail.startswith(message)
    assert snapshot(host) == before
    assert fake_runner.calls == []


# --- guards ---------------------------------------------------------------------------


def test_guards_refuse_another_platform_and_a_non_root_caller(
    rctx, ctx_deck, release, host, fake_runner
):
    deck = release_ctx(ctx_deck, release)
    not_root = install(deck, release)
    (host / "etc/os-release").write_text("ID=debian\n", encoding="utf-8")
    off_platform = install(rctx, release)

    assert not_root.exit_code == ExitCode.NEEDS_ROOT
    assert not_root.lines == (
        StepLine("guards", "failed", "needs root: run it with sudo"),
    )
    assert off_platform.exit_code == ExitCode.UNSUPPORTED_PLATFORM
    assert off_platform.lines[0].detail == "unsupported platform: SteamOS only"
    assert fake_runner.calls == []


# --- repair (no --release), compile, flip ---------------------------------------------


def test_without_release_the_active_release_is_repaired(rctx, release, host, reloads):
    install(rctx, release)
    (host / ETC_FILES[1]).unlink()

    report = installer.install(rctx, release=None, start_present=False)

    assert report.exit_code == ExitCode.OK
    assert lines_of(report)["release"].detail == f"repair {RELEASE_NAME}"
    assert "compile" not in lines_of(report)
    assert statuses(report)[f"write /{ETC_FILES[1]}"] == "ok"
    assert (host / ETC_FILES[1]).exists()


@pytest.mark.parametrize("current", [None, "elsewhere/x", "releases/../x"])
def test_repair_without_an_active_release_exits_5(
    rctx, release, host, fake_runner, current
):
    if current is not None:
        (host / CURRENT).symlink_to(current)

    report = installer.install(rctx, release=None)

    assert report.exit_code == ExitCode.PARTIAL
    assert report.lines[-1].detail == "no active release to repair: run install.sh"


def test_a_release_that_does_not_compile_is_never_activated(
    rctx, release, host, fake_runner
):
    broken = release / "lib/steamos_mounter/broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    broken.chmod(0o644)

    report = install(rctx, release)

    assert report.exit_code == ExitCode.PARTIAL
    assert report.lines[-1] == StepLine(
        "compile", "failed", "the release could not be compiled: run install.sh"
    )
    assert not os.path.lexists(host / CURRENT)
    assert fake_runner.calls == []


def test_install_compiles_the_release(rctx, release, reloads):
    install(rctx, release)

    assert list((release / "lib/steamos_mounter/__pycache__").glob("__init__.*.pyc"))


def test_a_failed_flip_stops_before_any_etc_file(rctx, release, host, fake_runner):
    (host / CURRENT).mkdir()
    (host / CURRENT / "keep").write_text("x", encoding="utf-8")

    report = install(rctx, release)

    assert report.exit_code == ExitCode.PARTIAL
    assert report.lines[-1].step == "current"
    assert not any((host / path).exists() for path in ETC_FILES)
    assert fake_runner.calls == []


def test_the_flip_replaces_the_previous_release_link(rctx, release, host, reloads):
    old = stage_release(host, "0.0.9-20261001T000000Z", package=False)
    (host / CURRENT).symlink_to(f"releases/{old.name}")

    report = install(rctx, release)

    assert lines_of(report)["current"] == StepLine(
        "current", "ok", f"releases/{RELEASE_NAME}"
    )
    assert os.readlink(host / CURRENT) == f"releases/{RELEASE_NAME}"


# --- file rows ------------------------------------------------------------------------


@pytest.mark.parametrize("spoil", ["content", "mode", "symlink"])
def test_a_file_row_is_rewritten_when_it_differs(rctx, release, host, reloads, spoil):
    install(rctx, release)
    path = host / ETC_FILES[0]
    if spoil == "content":
        path.write_text("hand edit\n", encoding="utf-8")
    elif spoil == "mode":
        path.chmod(0o600)
    else:
        path.unlink()
        path.symlink_to(release / "data/steamos-mounter.conf")

    report = install(rctx, release)

    assert statuses(report)[f"write /{ETC_FILES[0]}"] == "ok"
    assert not path.is_symlink()
    assert mode_of(path) == 0o644
    assert path.read_bytes() == (release / "data/steamos-mounter.conf").read_bytes()


def test_a_file_owned_by_another_uid_is_rewritten(
    rctx, release, host, reloads, monkeypatch
):
    install(rctx, release)
    path = host / ETC_FILES[0]
    lstat = os.lstat

    def foreign(target, *args, **kwargs):
        info = lstat(target, *args, **kwargs)
        if os.fspath(target) != os.fspath(path):
            return info
        fields = list(info)
        fields[stat.ST_UID] = os.getuid() + 1
        return os.stat_result(fields)

    monkeypatch.setattr(os, "lstat", foreign)
    report = install(rctx, release)

    assert statuses(report)[f"write /{ETC_FILES[0]}"] == "ok"


# --- kept registry (ADR-0004 D8.6) ----------------------------------------------------


def write_kept(host: Path, text: str, mode: int = 0o644) -> Path:
    kept = host / KEPT_REGISTRY
    kept.parent.mkdir(parents=True, exist_ok=True)
    kept.parent.chmod(0o755)
    kept.write_text(text, encoding="utf-8")
    kept.chmod(mode)
    return kept


def test_a_kept_registry_is_moved_back_and_wired(rctx, release, host, reloads):
    write_kept(host, MEDIABOX_REGISTRY)

    report = install(rctx, release)

    assert report.exit_code == ExitCode.OK
    assert (host / REGISTRY).read_text(encoding="utf-8") == MEDIABOX_REGISTRY
    assert mode_of(host / REGISTRY) == 0o644
    assert not (host / KEPT_REGISTRY).exists()
    assert lines_of(report)["kept registry"] == StepLine(
        "kept registry",
        "ok",
        "restored /etc/steamos-mounter/config.toml from "
        "/var/lib/steamos-mounter/kept-config.toml",
    )
    assert os.readlink(host / MEDIABOX_LINK) == TEMPLATE


def test_a_kept_registry_with_an_invalid_entry_comes_back_byte_for_byte(
    rctx, release, host, reloads
):
    """The restore copies bytes: an invalid hand-edited entry is never dropped."""
    text = MEDIABOX_REGISTRY + (
        '\n[[volume]]\nname = "GAMES"\nuuid = "1234-ABCD"\npath = "/mnt/GAMES"\n'
        'fstype = "exfat"\n'
    )
    write_kept(host, text)

    report = install(rctx, release)

    assert report.exit_code == ExitCode.OK
    assert (host / REGISTRY).read_text(encoding="utf-8") == text
    assert os.readlink(host / MEDIABOX_LINK) == TEMPLATE


@pytest.mark.parametrize(
    ("text", "mode"),
    [(BROKEN_REGISTRY, 0o644), (MEDIABOX_REGISTRY, 0o666), ("\udcff", 0o644)],
    ids=["schema", "writable", "not-utf8"],
)
def test_an_unusable_kept_registry_stays_and_is_reported_last(
    rctx, release, host, reloads, text, mode
):
    kept = host / KEPT_REGISTRY
    write_kept(host, "x", mode)
    kept.write_bytes(text.encode("utf-8", "surrogateescape"))
    before = kept.read_bytes()

    report = install(rctx, release)

    assert report.exit_code == ExitCode.PARTIAL
    assert report.lines[-1] == StepLine(
        "kept registry",
        "failed",
        "kept registry unusable: left in place at "
        "/var/lib/steamos-mounter/kept-config.toml",
    )
    assert kept.read_bytes() == before
    assert not (host / REGISTRY).exists()


def test_when_both_registries_exist_etc_wins_with_a_warning(
    rctx, release, host, reloads
):
    write_registry(host, MEDIABOX_REGISTRY)
    kept = write_kept(host, BROKEN_REGISTRY)

    report = install(rctx, release)

    assert report.exit_code == ExitCode.OK
    line = lines_of(report)["kept registry"]
    assert line.status == "skipped"
    assert line.detail.startswith("warning: ")
    assert kept.read_text(encoding="utf-8") == BROKEN_REGISTRY
    assert (host / REGISTRY).read_text(encoding="utf-8") == MEDIABOX_REGISTRY


# --- wiring ---------------------------------------------------------------------------


def test_an_unusable_registry_leaves_the_wiring_and_exits_5(
    rctx, release, host, reloads
):
    write_registry(host, MEDIABOX_REGISTRY)
    install(rctx, release)
    write_registry(host, BROKEN_REGISTRY)

    report = install(rctx, release, start_present=True)

    assert report.exit_code == ExitCode.PARTIAL
    assert report.lines[-1] == StepLine(
        "wiring", "failed", "registry unusable: wiring unchanged"
    )
    assert os.readlink(host / MEDIABOX_LINK) == TEMPLATE
    assert lines_of(report)["start"] == StepLine(
        "start", "skipped", "registry unusable: wiring unchanged"
    )
    assert lines_of(report)["daemon-reload"].status == "ok"


def test_reloads_run_once_each_after_the_links(rctx, release, host, fake_runner):
    write_registry(host, MEDIABOX_REGISTRY)
    seen: list[bool] = []
    fake_runner.on(
        DAEMON_RELOAD,
        Answer(),
        hook=lambda _cmd: seen.append(os.path.islink(host / MEDIABOX_LINK)),
    )
    fake_runner.on(UDEVADM_RELOAD, Answer())
    fake_runner.on(SETFACL, Answer())

    install(rctx, release)

    assert fake_runner.argvs == [
        DAEMON_RELOAD,
        UDEVADM_RELOAD,
        (SETFACL, "-m", "u:1000:r-x", "/run/media/deck"),
    ]
    assert seen == [True]


def test_a_failed_step_is_printed_last_and_the_rest_still_runs(
    rctx, release, host, fake_runner
):
    fake_runner.on(DAEMON_RELOAD, Answer(returncode=1, stderr=b"boom"))
    fake_runner.on(UDEVADM_RELOAD, Answer(returncode=1))
    fake_runner.on(SETFACL, Answer())

    report = install(rctx, release)

    assert report.exit_code == ExitCode.PARTIAL
    assert [line.step for line in report.lines[-2:]] == [
        "daemon-reload",
        "udevadm reload",
    ]
    assert report.lines[-1].detail == "udev could not reload its rules"
    assert lines_of(report)["mount base"].status == "ok"
    assert lines_of(report)["prune"].status == "skipped"


# --- start (--no-start, present devices) ----------------------------------------------


def test_no_start_starts_nothing(rctx, release, host, reloads):
    write_registry(host, MEDIABOX_REGISTRY)

    report = install(rctx, release, start_present=False)

    assert lines_of(report)["start"] == StepLine("start", "skipped", "--no-start")
    assert not [argv for argv in reloads.argvs if "show" in argv or "start" in argv]


def given_present_devices(host: Path, host_tree, runner) -> None:
    """MEDIABOX (registered, plugged), GAMES (exFAT stick), an ext4 disk."""
    write_registry(host, MEDIABOX_REGISTRY)
    known_os_set(host)
    host_tree.link_by_uuid(MEDIABOX_UUID, "sdb5")
    host_tree.add_block(SysfsDevice(kname="sdc1", devnum="8:33"))
    script_tree(
        runner,
        tree_with(
            partition("sdb5", fstype="ntfs", uuid=MEDIABOX_UUID, label="MEDIABOX"),
            partition("sdc1", fstype="exfat", uuid="AB12-CD34", label="GAMES"),
            partition("sda1", fstype="ext4", uuid="4af5710c", label="EXT256"),
            # Listed by lsblk but gone from sysfs: unplugged mid-install.
            partition("sdd1", fstype="exfat", uuid="EF01-2345", label="GONE"),
        ),
    )


def test_inactive_instances_of_present_devices_are_started(
    rctx, release, host, host_tree, reloads
):
    given_present_devices(host, host_tree, reloads)
    script_unit(reloads, MEDIABOX_UNIT, "inactive")
    script_unit(reloads, GAMES_UNIT, "failed")
    reloads.on(verb_argv("start", MEDIABOX_UNIT, block=False), Answer())
    reloads.on(verb_argv("start", GAMES_UNIT, block=False), Answer())

    report = install(rctx, release, start_present=True)

    assert report.exit_code == ExitCode.OK
    assert lines_of(report)["start"] == StepLine("start", "ok", "2 present")
    assert statuses(report)["start MEDIABOX"] == "ok"
    assert statuses(report)["start /dev/sdc1"] == "ok"
    starts = [argv for argv in reloads.argvs if argv[1:2] == ("start",)]
    assert starts == [
        verb_argv("start", MEDIABOX_UNIT, block=False),
        verb_argv("start", GAMES_UNIT, block=False),
    ]


def test_an_active_instance_is_never_restarted(rctx, release, host, host_tree, reloads):
    given_present_devices(host, host_tree, reloads)
    script_unit(reloads, MEDIABOX_UNIT, "active")
    reloads.on(
        ("/usr/bin/systemctl", "show"),
        Answer(stdout=b"LoadState=not-found\nActiveState=inactive\n"),
    )
    reloads.on(verb_argv("start", GAMES_UNIT, block=False), Answer())

    report = install(rctx, release, start_present=True)

    assert lines_of(report)["start MEDIABOX"] == StepLine(
        "start MEDIABOX", "skipped", "active"
    )
    assert statuses(report)["start /dev/sdc1"] == "ok"
    verbs = {argv[1] for argv in reloads.argvs if argv[0] == "/usr/bin/systemctl"}
    assert verbs.isdisjoint({"stop", "restart", "reload"})


def test_a_failed_start_is_a_failed_step(rctx, release, host, host_tree, reloads):
    write_registry(host, MEDIABOX_REGISTRY)
    host_tree.link_by_uuid(MEDIABOX_UUID, "sdb5")
    script_tree(reloads, tree_with())
    script_unit(reloads, MEDIABOX_UNIT, "inactive")
    reloads.on(verb_argv("start", MEDIABOX_UNIT, block=False), Answer(returncode=1))

    report = install(rctx, release, start_present=True)

    assert report.exit_code == ExitCode.PARTIAL
    assert report.lines[-1] == StepLine(
        "start MEDIABOX", "failed", "the instance did not start: run install.sh again"
    )


def test_nothing_present_is_one_skipped_start_line(rctx, release, host, reloads):
    script_tree(reloads, tree_with())

    report = install(rctx, release, start_present=True)

    assert lines_of(report)["start"] == StepLine(
        "start", "skipped", "no present device to start"
    )


def test_an_unreadable_device_tree_is_a_failed_start(rctx, release, host, reloads):
    reloads.on(LSBLK_ARGV, Answer(returncode=1))

    report = install(rctx, release, start_present=True)

    assert report.lines[-1].step == "start"
    assert report.lines[-1].status == "failed"


# --- mount base, prune ----------------------------------------------------------------


def test_the_mount_base_is_made_once(rctx, release, host, reloads):
    first = install(rctx, release)
    second = install(rctx, release)

    assert lines_of(first)["mount base"] == StepLine(
        "mount base", "ok", "/run/media/deck"
    )
    assert lines_of(second)["mount base"].status == "skipped"
    assert [argv[0] for argv in reloads.argvs].count(SETFACL) == 1


@pytest.mark.parametrize(
    ("names", "current", "kept"),
    [
        # 0.9 -> 0.10: name order would put 0.10.0 first and delete 0.9.0.
        (("0.9.0-20261001T000000Z",), "0.10.0-20261002T000000Z", 0),
        (
            ("0.9.0-20261001T000000Z", "0.10.0-20261002T000000Z"),
            "0.10.1-20261003T000000Z",
            1,
        ),
        # A downgrade keeps the release that was active before it (0.10.0);
        # name order would keep 0.9.0 instead.
        (
            ("0.9.0-20261001T000000Z", "0.10.0-20261002T000000Z"),
            "0.9.1-20261003T000000Z",
            1,
        ),
    ],
    ids=["0.9-to-0.10", "0.10.0-to-0.10.1", "downgrade"],
)
def test_prune_orders_releases_by_install_stamp_not_by_name(
    ctx, host, reloads, names, current, kept
):
    for name in names:
        stage_release(host, name, package=False)
    release = stage_release(host, current, package=False)

    install(release_ctx(ctx, release), release)

    assert sorted(os.listdir(host / RELEASES)) == sorted([names[kept], current])


def test_prune_without_a_stamp_keeps_only_current(ctx, host, reloads):
    stage_release(host, "0.1.0-20261001T000000Z", package=False)
    release = stage_release(host, "dev", package=False)

    install(release_ctx(ctx, release), release)

    assert os.listdir(host / RELEASES) == ["dev"]


def test_install_runs_with_umask_022_and_restores_the_callers(rctx, release, reloads):
    previous = os.umask(0o002)
    try:
        report = install(rctx, release)
        during_restore = os.umask(0o002)
    finally:
        os.umask(previous)

    assert report.exit_code == ExitCode.OK
    assert during_restore == 0o002
    pycache = release / "lib/steamos_mounter/__pycache__"
    assert mode_of(pycache) == 0o755  # 0775 under umask 002: the trust check refuses
    assert installer.tree_problem(release, os.getuid()) is None


def test_uninstall_restores_the_callers_umask(ctx, host, fake_runner):
    previous = os.umask(0o002)
    try:
        installer.uninstall(ctx, purge=False)
        after = os.umask(previous)
    finally:
        os.umask(previous)

    assert after == 0o002


def test_prune_keeps_current_and_the_one_before(rctx, release, host, reloads):
    names = [
        "0.0.7-20261001T000000Z",
        "0.0.8-20261002T000000Z",
        "0.0.9-20261003T000000Z",
        "0.2.0-20261020T000000Z",  # a partial release from a failed later run
    ]
    for name in names:
        stage_release(host, name, package=False)
    (host / RELEASES / "stray").write_text("x", encoding="utf-8")

    report = install(rctx, release)

    assert sorted(os.listdir(host / RELEASES)) == [names[2], RELEASE_NAME]
    assert lines_of(report)["prune"].detail == (
        f"removed {names[0]}, {names[1]}, {names[3]}, stray"
    )


# --- output ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "text"),
    [
        (StepLine("prune", "skipped", ""), "steamos-mounter install: prune: skipped"),
        (
            StepLine("wiring", "failed", "registry unusable: wiring unchanged"),
            "steamos-mounter install: wiring: failed: registry unusable: wiring "
            "unchanged",
        ),
    ],
)
def test_render_prefixes_every_line(line, text):
    assert render(installer_report.INSTALL, line) == text


def test_the_install_command_prints_the_step_lines(rctx, release, host, reloads):
    result = run_cli(rctx, "install", "--release", str(release), "--no-start")

    assert result.code == ExitCode.OK
    assert result.err == ""
    lines = result.out.splitlines()
    assert lines[0] == f"steamos-mounter install: release: ok: {RELEASE_NAME}"
    assert all(line.startswith("steamos-mounter install: ") for line in lines)
    assert "steamos-mounter install: start: skipped: --no-start" in lines


# --- shared helpers -------------------------------------------------------------------


def test_ensure_dir_sets_the_trusted_owner_of_an_existing_directory(
    ctx, tmp_path, monkeypatch
):
    (tmp_path / "etc/steamos-mounter").mkdir(parents=True, mode=0o755)
    chowned: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "getegid", lambda: 4242)
    monkeypatch.setattr(os, "fchown", lambda _fd, uid, gid: chowned.append((uid, gid)))

    changed = installer_report.ensure_dir(ctx, "/etc/steamos-mounter", 0o755)

    assert changed is True
    assert chowned == [(os.getuid(), 4242)]


def test_a_manifest_row_without_its_mode_is_unusable():
    row = Entry("dir", "/var/lib/steamos-mounter", "root:root", None, "-", "state")

    with pytest.raises(MounterError, match="the install manifest is unusable"):
        installer_report.row_mode(row)
    with pytest.raises(MounterError, match="the install manifest is unusable"):
        installer_report.dir_mode((), "/var/lib/steamos-mounter")


def test_remove_path_unlinks_a_symlink_and_never_follows_it(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep").write_text("x", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)

    assert installer_report.remove_path(link) is True
    assert installer_report.remove_path(link) is False
    assert (target / "keep").exists()
