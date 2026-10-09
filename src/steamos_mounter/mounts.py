"""The mount table as findmnt shows it: read-back, the list, the held check.

Design Doc "blockdev, mounts, naming, escape", "Read-back and State" and the
Fact Disposition Table row for findmnt, the only truth for driver and mode.

- Exit 1 with no output means "nothing mounted there", never a tool failure;
  any other non-zero exit, a timeout or a missing binary is a ``ToolError``
  (IP-05).
- Options stay two lists, VFS and FS, split on commas.
- ``maj:min`` may be absent (captures made without the column) or anonymous
  (btrfs ``0:28``, every FUSE mount), so ``for_device`` also matches on the
  source with a bind ``[/subpath]`` stripped.
"""

import json
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final

from steamos_mounter.blockdev import BlockDevice
from steamos_mounter.errors import ToolError
from steamos_mounter.model import MountInfo
from steamos_mounter.runner import TEXT_ERRORS, Command, CommandResult

if TYPE_CHECKING:
    from steamos_mounter.context import Context

FINDMNT_COLUMNS: Final = "TARGET,SOURCE,FSTYPE,VFS-OPTIONS,FS-OPTIONS,MAJ:MIN"
FINDMNT_TIMEOUT: Final = 10.0
NOTHING_FOUND: Final = 1  # findmnt's exit status when no mount matches

# findmnt spells each JSON key as the lowercased column name.
_TARGET, _SOURCE, _FSTYPE, _VFS_OPTIONS, _FS_OPTIONS, _DEVNUM = (
    column.lower() for column in FINDMNT_COLUMNS.split(",")
)
_ROOT_KEY: Final = "filesystems"
_CHILDREN_KEY: Final = "children"
_SUBPATH_START: Final = "[/"
_READ_FAILED: Final = "cannot read the mount table"


def parse_findmnt(result: CommandResult) -> tuple[MountInfo, ...]:
    """Every row of a ``findmnt --json`` run, nested children flattened in order.

    Exit 1 with empty stdout gives ``()``. Bytes are decoded as UTF-8 with
    ``surrogateescape`` (DD-01).
    """
    if result.returncode == NOTHING_FOUND and not result.stdout:
        return ()
    if result.returncode != 0:
        raise ToolError(
            _READ_FAILED,
            detail=(
                f"findmnt: exit {result.returncode}, timed out {result.timed_out}, "
                f"not found {result.not_found}: {result.err_text().strip()}"
            ),
        )
    try:
        document = json.loads(result.stdout.decode("utf-8", TEXT_ERRORS))
    except ValueError as error:
        raise ToolError(_READ_FAILED, detail=f"findmnt: not JSON: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get(_ROOT_KEY), list):
        raise ToolError(_READ_FAILED, detail=f"findmnt: no {_ROOT_KEY!r} list")
    rows: list[MountInfo] = []
    _collect(document[_ROOT_KEY], rows)
    return tuple(rows)


def at_target(ctx: "Context", target: str) -> MountInfo | None:
    """The mount at ``target`` (the topmost when stacked), or None."""
    if not target.startswith("/"):
        raise ValueError(f"mount target must be absolute: {target!r}")
    rows = _run(ctx, "--mountpoint", target)
    return rows[-1] if rows else None


def table(ctx: "Context") -> tuple[MountInfo, ...]:
    """Every real mount, from one ``--list --real`` call."""
    return _run(ctx, "--list", "--real")


def for_device(
    table: Sequence[MountInfo], dev: BlockDevice, dm: str | None
) -> tuple[MountInfo, ...]:
    """Rows that mount ``dev``: same ``MAJ:MIN``, or a canonical source naming it.

    The names are ``dev.path``, ``/dev/<kname>`` and, when ``dm`` (the
    mapping's ``dm/name``) is given, ``/dev/mapper/<dm>``.
    """
    names = {dev.path, f"/dev/{dev.kname}"}
    if dm is not None:
        names.add(f"/dev/mapper/{dm}")
    return tuple(
        info
        for info in table
        if info.devnum == dev.devnum or canonical_source(info.source) in names
    )


def canonical_source(source: str) -> str:
    """``source`` without a bind mount's ``[/subpath]`` suffix.

    A device path cannot hold ``[/`` (no ``/`` in a dm name), so the first
    ``[/`` of a source ending in ``]`` starts the subpath.
    """
    head, found, _ = source.partition(_SUBPATH_START)
    return head if found and source.endswith("]") else source


def _run(ctx: "Context", *selection: str) -> tuple[MountInfo, ...]:
    argv = (ctx.platform.tools.findmnt, "--json", "-o", FINDMNT_COLUMNS, *selection)
    return parse_findmnt(ctx.runner.run(Command(argv=argv, timeout=FINDMNT_TIMEOUT)))


def _collect(nodes: list[Any], rows: list[MountInfo]) -> None:
    for node in nodes:
        rows.append(_row(node))
        children = node.get(_CHILDREN_KEY, [])
        if not isinstance(children, list):
            raise ToolError(_READ_FAILED, detail="findmnt: children is not a list")
        _collect(children, rows)


def _row(node: object) -> MountInfo:
    if not isinstance(node, dict):
        raise ToolError(_READ_FAILED, detail="findmnt: row is not an object")
    return MountInfo(
        target=_text(node, _TARGET),
        source=_text(node, _SOURCE),
        fstype=_text(node, _FSTYPE),
        vfs_options=_options(node, _VFS_OPTIONS),
        fs_options=_options(node, _FS_OPTIONS),
        devnum=_optional_text(node, _DEVNUM),
    )


def _text(node: dict[str, Any], key: str) -> str:
    value = node.get(key)
    if not isinstance(value, str):
        raise ToolError(_READ_FAILED, detail=f"findmnt column {key}: {value!r}")
    return value


def _optional_text(node: dict[str, Any], key: str) -> str | None:
    if node.get(key) is None:
        return None
    return _text(node, key)


def _options(node: dict[str, Any], key: str) -> tuple[str, ...]:
    value = _optional_text(node, key)
    return tuple(value.split(",")) if value else ()
