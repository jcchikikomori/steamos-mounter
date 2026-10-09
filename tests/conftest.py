"""Shared pytest fixtures.

Design Doc "Mock Boundary Decisions": the clock is faked; sysfs and /dev/disk
are real files under ``tmp_path``. Later phases add ``fake_runner``,
``fake_platform``, ``fake_kmsg`` and ``ctx`` here.
"""

from pathlib import Path

import pytest

from tests.helpers.clock import FakeClock
from tests.helpers.host_tree import HostTree


@pytest.fixture
def fake_clock() -> FakeClock:
    """A clock at the default start that moves only on ``advance``."""
    return FakeClock()


@pytest.fixture
def host_tree(tmp_path: Path) -> HostTree:
    """An empty host tree rooted at ``tmp_path`` (``HostPaths(root=tmp_path)``)."""
    return HostTree(tmp_path)
