"""Shared pytest fixtures.

Design Doc "Mock Boundary Decisions": the clock is faked; sysfs and /dev/disk
are real files under ``tmp_path``; the journald socket is a real datagram
socket under ``tmp_path``; external commands go through the scripted
``fake_runner``; the platform is ``FakePlatform`` (SteamOS facts, the test
uid as ``trusted_uid``); ``/dev/kmsg`` is ``FakeKernelLog``. ``ctx`` bundles
them as a root entry started by systemd, ``ctx_deck`` as the ``deck`` user.
"""

import logging
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from steamos_mounter import blockdev
from steamos_mounter.context import Context
from steamos_mounter.journal import JournalHandler, setup_logging
from steamos_mounter.platforms.base import HostPaths
from tests.helpers.clock import FakeClock
from tests.helpers.fake_kmsg import FakeKernelLog
from tests.helpers.fake_platform import DECK_UID, FakePlatform
from tests.helpers.fake_runner import FakeRunner
from tests.helpers.host_tree import HostTree
from tests.helpers.journal_socket import JournalReceiver

LoggingSetup = Callable[..., list[logging.Handler]]
# Tests only: a send that cannot complete fails the test instead of hanging it.
JOURNAL_SEND_TIMEOUT = 30.0
# The shape systemd gives $INVOCATION_ID: 32 lowercase hex digits.
TEST_INVOCATION_ID = "0f6c9c1e5c7a4c51a0a5f3f3b2b6d7e8"


@pytest.fixture
def fake_clock() -> FakeClock:
    """A clock at the default start that moves only on ``advance``."""
    return FakeClock()


@pytest.fixture
def host_tree(tmp_path: Path) -> HostTree:
    """An empty host tree rooted at ``tmp_path`` (``HostPaths(root=tmp_path)``)."""
    return HostTree(tmp_path)


@pytest.fixture
def fake_runner() -> Iterator[FakeRunner]:
    """A runner with no scripts yet; teardown fails on any unexpected command."""
    runner = FakeRunner()
    yield runner
    runner.finish()


@pytest.fixture
def fake_platform() -> FakePlatform:
    """SteamOS facts with ``trusted_uid`` = the test uid."""
    return FakePlatform()


@pytest.fixture
def fake_kmsg() -> FakeKernelLog:
    """An empty kernel log; ``queue`` lines the next step should see."""
    return FakeKernelLog()


@pytest.fixture
def ctx(
    tmp_path: Path,
    fake_runner: FakeRunner,
    fake_platform: FakePlatform,
    fake_clock: FakeClock,
    fake_kmsg: FakeKernelLog,
) -> Context:
    """A root entry started by systemd, on the host tree under ``tmp_path``."""
    return Context(
        runner=fake_runner,
        platform=fake_platform,
        paths=HostPaths(root=tmp_path),
        clock=fake_clock,
        kmsg=fake_kmsg,
        euid=0,
        invocation_id=TEST_INVOCATION_ID,
    )


@pytest.fixture
def ctx_deck(
    tmp_path: Path,
    fake_runner: FakeRunner,
    fake_platform: FakePlatform,
    fake_clock: FakeClock,
    fake_kmsg: FakeKernelLog,
) -> Context:
    """The ``deck`` user from a terminal: euid 1000, no systemd invocation."""
    return Context(
        runner=fake_runner,
        platform=fake_platform,
        paths=HostPaths(root=tmp_path),
        clock=fake_clock,
        kmsg=fake_kmsg,
        euid=DECK_UID,
        invocation_id=None,
    )


@pytest.fixture
def no_holders(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fails the test when anything reads sysfs ``holders/`` (ADR-0001 guidance 10)."""

    def forbidden(*_args: object) -> list[str]:
        raise AssertionError("teardown read sysfs holders/")

    monkeypatch.setattr(blockdev, "holders", forbidden)


@pytest.fixture
def journal_receiver(tmp_path: Path) -> Iterator[JournalReceiver]:
    """A real journald stand-in bound at ``tmp_path / "j"`` (short: sun_path)."""
    receiver = JournalReceiver(tmp_path / "j")
    yield receiver
    receiver.close()


@pytest.fixture
def logging_setup(monkeypatch: pytest.MonkeyPatch) -> Iterator[LoggingSetup]:
    """Runs ``setup_logging`` on an emptied root logger and undoes it at teardown.

    The root handler list is emptied when the factory is called, inside the
    test, because pytest adds its capture handlers just before the test body.
    Those handlers would keep unredacted text of the records under test, and
    print it on a failure, so they must not see them.

    A journal handler's socket gets a send timeout here, and only here: in
    production it blocks like journald's own clients. Should the receiver stop
    reading, a test then fails with a logging error instead of hanging.
    """
    root = logging.getLogger()
    level = root.level
    created: list[logging.Handler] = []

    def setup(component: str, **kwargs: object) -> list[logging.Handler]:
        monkeypatch.setattr(root, "handlers", [])
        handlers = setup_logging(component, **kwargs)
        created.extend(handlers)
        for handler in handlers:
            if isinstance(handler, JournalHandler):
                handler._socket.settimeout(JOURNAL_SEND_TIMEOUT)
        return handlers

    yield setup
    for handler in created:
        root.removeHandler(handler)
        handler.close()
    root.setLevel(level)
