"""A ``Platform`` for tests: SteamOS facts with the test user as the owner.

Design Doc "Mock Boundary Decisions" and AC-052: every routing and flow test
runs on ``FakePlatform``. It differs from ``SteamOSPlatform`` in two places
only:

- ``trusted_uid`` is the test user's uid, so owner checks run against real
  files the test created under ``tmp_path``;
- ``session_user`` is the Deck's ``deck`` (uid 1000) without a ``pwd``
  lookup; the Docker image has no such user.

Detection, the OS partition set and the holo lock path run the real SteamOS
code, so tests set them up with real files under ``HostPaths(root=tmp_path)``
(the ``host_tree`` fixture's ``link_by_partsets``, the holo rules file).
It carries exactly the ``Platform`` members, nothing a caller could come to
rely on that production lacks.
"""

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from steamos_mounter.platforms import steamos
from steamos_mounter.platforms.base import (
    HostPaths,
    OsPartitionSet,
    SessionAllowList,
    SessionUser,
    Tools,
)

if TYPE_CHECKING:
    from steamos_mounter.context import Context

DECK_UID = 1000
DECK_SESSION = SessionUser(
    name="deck",
    uid=DECK_UID,
    gid=DECK_UID,
    runtime_dir=f"/run/user/{DECK_UID}",
    bus_address=f"unix:path=/run/user/{DECK_UID}/bus",
)
_STEAMOS = steamos.SteamOSPlatform()


@dataclass(frozen=True, slots=True, kw_only=True)
class FakePlatform:
    name: str = "steamos"
    tools: Tools = steamos.TOOLS
    mount_base: str = steamos.MOUNT_BASE
    trusted_uid: int = field(default_factory=os.getuid)
    auto_fstypes: frozenset[str] = steamos.AUTO_FSTYPES
    registrable_fstypes: frozenset[str] = steamos.REGISTRABLE_FSTYPES
    keep_list: str = steamos.KEEP_LIST
    dropin_dir: str = steamos.DROPIN_DIR
    allow_list: SessionAllowList = steamos.ALLOW_LIST
    xauthority_from_xserver: bool = False
    dialog_tool: str = steamos.DIALOG_TOOL
    cli_root: str = steamos.CLI_ROOT

    def detect(self, paths: HostPaths) -> bool:
        return _STEAMOS.detect(paths)

    def session_user(self) -> SessionUser:
        return DECK_SESSION

    def os_partitions(self, ctx: "Context", *, as_root: bool) -> OsPartitionSet:
        return _STEAMOS.os_partitions(ctx, as_root=as_root)

    def automount_lock_path(self, kname: str) -> str | None:
        return _STEAMOS.automount_lock_path(kname)
