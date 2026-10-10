"""The ``.device.wants`` links that start registered instances, from the registry.

Design Doc "session, dialog, notify, systemd, wiring", "Interface Change
Matrix" and "Keep-list Drop-in"; ADR-0002 D1 and D6.2. Each registered
volume gets one symlink

    /etc/systemd/system/<instance>.device.wants/steamos-mounter@<instance>.service
        -> /etc/systemd/system/steamos-mounter@.service

where ``<instance>`` is the escaped ``/dev/disk/by-uuid/<UUID>`` path, so the
by-uuid device unit starts the registered instance when it is plugged. The
UUID keeps the case the registry (and udev's by-uuid link) spells it in.

Links are only ever regenerated, never edited in place: ``sync_links``
creates the missing ones (a link with another target is replaced in one
rename and counted as created), removes the ones no entry needs, and removes
a ``.device.wants`` directory it emptied. An invalid entry whose UUID is
valid keeps its link: its instance then records ``registry_entry_invalid``
instead of staying silent (Design Doc "Validation on Every Read"). There is
no limit on the number of links (NFR-25).

The caller saves the registry first and runs ``systemd.daemon_reload`` after
this step (planner default 4).
"""

import errno
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from steamos_mounter.atomicfile import replace_symlink
from steamos_mounter.errors import MounterError
from steamos_mounter.escape import SERVICE_SUFFIX, registered_instance, unit_name
from steamos_mounter.model import Registry
from steamos_mounter.routing import REGISTERED_TEMPLATE

if TYPE_CHECKING:
    from steamos_mounter.context import Context

SYSTEMD_DIR: Final = "/etc/systemd/system"
TEMPLATE_PATH: Final = f"{SYSTEMD_DIR}/{REGISTERED_TEMPLATE}{SERVICE_SUFFIX}"
WANTS_SUFFIX: Final = ".device.wants"
WANTS_MODE: Final = 0o755
WIRING_FAILED: Final = "the systemd wiring could not be updated"

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class WiringChange:
    created: tuple[str, ...]
    removed: tuple[str, ...]


def expected_links(registry: Registry) -> dict[str, str]:
    """Link path -> ``TEMPLATE_PATH`` for every entry that has a UUID."""
    uuids = [volume.uuid for volume in registry.volumes]
    uuids += [entry.uuid for entry in registry.invalid if entry.uuid is not None]
    return {_link_path(uuid): TEMPLATE_PATH for uuid in sorted(set(uuids))}


def existing_links(ctx: "Context") -> dict[str, str]:
    """This tool's links found now: link path -> what it points at.

    Only symlinks named ``steamos-mounter@*.service`` inside a real
    ``*.device.wants`` directory count; anything else there is not ours.
    """
    root = ctx.paths.p(SYSTEMD_DIR)
    try:
        names = sorted(os.listdir(root))
    except FileNotFoundError:
        return {}
    found: dict[str, str] = {}
    for name in names:
        if name.endswith(WANTS_SUFFIX) and _is_real_dir(root / name):
            found.update(_links_in(ctx, f"{SYSTEMD_DIR}/{name}"))
    return found


def sync_links(ctx: "Context", registry: Registry) -> WiringChange:
    """Make the links on disk equal ``expected_links(registry)``.

    Raises ``MounterError`` when a ``.device.wants`` name is not a real
    directory, and lets ``OSError`` from a write or a removal propagate.
    """
    expected = expected_links(registry)
    existing = existing_links(ctx)
    removed = tuple(path for path in existing if path not in expected)
    created = tuple(
        path for path, target in expected.items() if existing.get(path) != target
    )
    for path in removed:
        _remove(ctx, path)
    for path in created:
        _create(ctx, path, expected[path])
    return WiringChange(created=created, removed=removed)


def _link_path(uuid: str) -> str:
    instance = registered_instance(uuid)
    unit = unit_name(REGISTERED_TEMPLATE, instance)
    return f"{SYSTEMD_DIR}/{instance}{WANTS_SUFFIX}/{unit}"


def _is_real_dir(path: Path) -> bool:
    """A directory itself, not a symlink to one (``lstat``)."""
    return stat.S_ISDIR(os.lstat(path).st_mode)


def _links_in(ctx: "Context", wants_dir: str) -> dict[str, str]:
    directory = ctx.paths.p(wants_dir)
    found: dict[str, str] = {}
    for name in sorted(os.listdir(directory)):
        if not (name.startswith(REGISTERED_TEMPLATE) and name.endswith(SERVICE_SUFFIX)):
            continue
        if os.path.islink(directory / name):
            found[f"{wants_dir}/{name}"] = os.readlink(directory / name)
    return found


def _create(ctx: "Context", link: str, target: str) -> None:
    wants_dir = link.rpartition("/")[0]
    directory = ctx.paths.p(wants_dir)
    try:
        os.mkdir(directory, WANTS_MODE)
    except FileExistsError:
        pass
    else:
        os.chmod(directory, WANTS_MODE)
    if not _is_real_dir(directory):
        raise MounterError(WIRING_FAILED, detail=f"{wants_dir} is not a directory")
    replace_symlink(ctx.paths.p(link), target)
    log.info("wired %s", link)


def _remove(ctx: "Context", link: str) -> None:
    os.unlink(ctx.paths.p(link))
    log.info("unwired %s", link)
    try:
        os.rmdir(ctx.paths.p(link.rpartition("/")[0]))
    except OSError as error:
        if error.errno != errno.ENOTEMPTY:
            raise
