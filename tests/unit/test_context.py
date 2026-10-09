"""The dependency bundle and its production builder.

Design Doc "model, context, platforms" and D002: ``build_context`` creates the
``/run/steamos-mounter`` tree on every root entry, through the real
``records.ensure_runtime_dirs``. Root entries here get ``HostPaths`` rooted at
``tmp_path`` (the ``host_root`` fixture), so the tree is real files and the
real owner checks run. Work plan decision item 2: ``Context.release_root`` is
a keyword-only field so the installer's release check has a test seam.
"""

import dataclasses
import logging
import os
import stat
import time
from datetime import UTC
from pathlib import Path

import pytest

from steamos_mounter import context, kmsg
from steamos_mounter.context import Context, SystemClock, build_context
from steamos_mounter.errors import MounterError, UnsupportedPlatformError
from steamos_mounter.platforms.base import HostPaths
from steamos_mounter.runner import SubprocessRunner
from tests.helpers.fake_kmsg import FakeKernelLog

RELEASE = "/opt/steamos-mounter/releases/0.1.0-20261009T000000Z"
INVOCATION_ID = "0f6c9c1e5c7a4c51a0a5f3f3b2b6d7e8"
RUNTIME_MODES = {
    "run/steamos-mounter": 0o755,
    "run/steamos-mounter/records": 0o755,
    "run/steamos-mounter/records/registered": 0o755,
    "run/steamos-mounter/records/auto": 0o755,
    "run/steamos-mounter/locks": 0o700,
}


@pytest.fixture
def host_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """``build_context``'s host paths under ``tmp_path``, with ``/run`` as at boot."""
    (tmp_path / "run").mkdir()
    monkeypatch.setattr(context, "HostPaths", lambda: HostPaths(root=tmp_path))
    return tmp_path


@pytest.fixture
def production(monkeypatch: pytest.MonkeyPatch, fake_platform) -> None:
    """The pieces Docker cannot provide, swapped at their seams.

    The Docker image is Debian, so platform detection is pointed at the fake
    platform; ``DevKmsg`` lands in task 20, so a fake kernel log stands in;
    the root logger is emptied so the handler ``build_context`` installs is
    dropped again at teardown.
    """
    root = logging.getLogger()
    monkeypatch.setattr(root, "handlers", [])
    monkeypatch.setattr(root, "level", root.level)
    monkeypatch.setattr(context, "current_platform", lambda paths: fake_platform)
    monkeypatch.setattr(kmsg, "DevKmsg", FakeKernelLog, raising=False)
    monkeypatch.delenv("INVOCATION_ID", raising=False)


def as_euid(monkeypatch: pytest.MonkeyPatch, euid: int) -> None:
    monkeypatch.setattr(context.os, "geteuid", lambda: euid)


# --- Context ---------------------------------------------------------------


def test_context_fields_are_keyword_only(ctx):
    values = {field.name: getattr(ctx, field.name) for field in dataclasses.fields(ctx)}

    with pytest.raises(TypeError):
        Context(*values.values())


def test_context_release_root_defaults_to_none(ctx):
    assert ctx.release_root is None


def test_context_carries_release_root(ctx):
    carried = dataclasses.replace(ctx, release_root=RELEASE)

    assert carried.release_root == RELEASE
    assert carried.runner is ctx.runner


def test_context_is_frozen(ctx):
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.euid = 1000  # type: ignore[misc]


def test_ctx_fixture_is_a_root_entry_under_tmp_path(
    ctx, tmp_path, fake_runner, fake_platform, fake_clock, fake_kmsg
):
    assert ctx.euid == 0
    assert ctx.paths == HostPaths(root=tmp_path)
    assert (ctx.runner, ctx.platform, ctx.clock, ctx.kmsg) == (
        fake_runner,
        fake_platform,
        fake_clock,
        fake_kmsg,
    )
    assert ctx.invocation_id == INVOCATION_ID


def test_ctx_deck_fixture_is_the_deck_user_without_systemd(ctx_deck, tmp_path):
    assert ctx_deck.euid == 1000
    assert ctx_deck.invocation_id is None
    assert ctx_deck.paths == HostPaths(root=tmp_path)


# --- SystemClock -----------------------------------------------------------


def test_system_clock_now_is_utc():
    assert SystemClock().now().tzinfo is UTC


def test_system_clock_monotonic_follows_time_monotonic():
    before = time.monotonic()

    reading = SystemClock().monotonic()

    assert before <= reading <= time.monotonic()


# --- build_context ---------------------------------------------------------


@pytest.mark.usefixtures("production")
def test_build_context_as_root_creates_the_runtime_dirs(monkeypatch, host_root):
    as_euid(monkeypatch, 0)

    ctx = build_context(component="handler")

    assert ctx.euid == 0
    assert ctx.paths == HostPaths(root=host_root)
    for relative, mode in RUNTIME_MODES.items():
        path = host_root / relative
        assert path.is_dir()
        assert stat.S_IMODE(os.lstat(path).st_mode) == mode


@pytest.mark.usefixtures("production")
def test_build_context_as_deck_creates_nothing(monkeypatch, host_root):
    as_euid(monkeypatch, 1000)

    ctx = build_context(component="cli")

    assert os.listdir(host_root / "run") == []
    assert ctx.euid == 1000


@pytest.mark.usefixtures("production")
def test_build_context_wires_the_production_pieces(monkeypatch, fake_platform):
    as_euid(monkeypatch, 1000)

    ctx = build_context(component="cli")

    assert isinstance(ctx.runner, SubprocessRunner)
    assert ctx.platform is fake_platform
    assert ctx.paths == HostPaths()
    assert isinstance(ctx.clock, SystemClock)
    assert isinstance(ctx.kmsg, FakeKernelLog)
    assert ctx.invocation_id is None
    assert ctx.release_root is None


@pytest.mark.usefixtures("production", "host_root")
def test_build_context_carries_release_root_and_invocation_id(monkeypatch):
    as_euid(monkeypatch, 0)
    monkeypatch.setenv("INVOCATION_ID", INVOCATION_ID)

    ctx = build_context(component="installer", release_root=RELEASE)

    assert ctx.release_root == RELEASE
    assert ctx.invocation_id == INVOCATION_ID


@pytest.mark.usefixtures("production")
def test_build_context_treats_an_empty_invocation_id_as_unset(monkeypatch):
    as_euid(monkeypatch, 1000)
    monkeypatch.setenv("INVOCATION_ID", "")

    assert build_context(component="cli").invocation_id is None


@pytest.mark.usefixtures("production")
def test_build_context_sets_up_logging_for_the_component(monkeypatch, capsys):
    as_euid(monkeypatch, 1000)
    before = list(logging.getLogger().handlers)  # pytest's own capture handlers

    build_context(component="doctor")
    logging.getLogger("steamos_mounter.test").warning("context ready")

    added = [h for h in logging.getLogger().handlers if h not in before]
    assert len(added) == 1
    assert "context ready" in capsys.readouterr().err


def test_build_context_off_steamos_raises_and_creates_nothing(monkeypatch, host_root):
    def refuse(paths):
        raise UnsupportedPlatformError("unsupported platform: SteamOS only")

    root = logging.getLogger()
    monkeypatch.setattr(root, "handlers", [])
    monkeypatch.setattr(context, "current_platform", refuse)
    as_euid(monkeypatch, 0)

    with pytest.raises(UnsupportedPlatformError):
        build_context(component="handler")

    assert os.listdir(host_root / "run") == []


@pytest.mark.usefixtures("production")
def test_build_context_propagates_a_runtime_dir_failure(monkeypatch, host_root):
    elsewhere = host_root / "elsewhere"
    elsewhere.mkdir()
    (host_root / "run" / "steamos-mounter").symlink_to(elsewhere)
    as_euid(monkeypatch, 0)

    with pytest.raises(MounterError) as caught:
        build_context(component="handler")

    assert "symlink" in caught.value.detail
    assert os.listdir(elsewhere) == []
