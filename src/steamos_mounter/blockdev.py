"""Block devices: the lsblk tree, removable classification, kname rules, sysfs.

Design Doc "blockdev, mounts, naming, escape" and the Fact Disposition Table
row for lsblk. ``read_tree`` runs one ``lsblk --json --bytes --tree`` with
``LSBLK_COLUMNS``; ``parse_lsblk_json`` checks every requested column is
there with the JSON type lsblk gives it, and refuses anything else as a tool
failure (IP-04). Labels are kept verbatim: they are hostile input (the real
BitLocker label holds ``/``) and only ``naming`` turns them into paths.

Removable means the ``hotplug`` flag of the top-level disk reached through
``pkname``, because a mapping reports ``hotplug: false`` itself (``dm-0 ->
sdb1 -> sdb``). When that chain cannot be followed the answer is None, which
callers treat as internal (fail safe).

The sysfs readers take a validated kname, read under ``ctx.paths`` and treat a
missing entry as absent (IP-06); any other read error propagates.
"""

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from steamos_mounter.errors import InvalidKernelName, ToolError
from steamos_mounter.runner import TEXT_ERRORS, Command

if TYPE_CHECKING:
    from steamos_mounter.context import Context

LSBLK_COLUMNS: Final = (
    "NAME,KNAME,PATH,MAJ:MIN,TYPE,FSTYPE,FSVER,LABEL,UUID,PTUUID,PTTYPE,PARTUUID,"
    "PARTLABEL,PARTTYPENAME,PKNAME,HOTPLUG,RM,RO,TRAN,SIZE,MOUNTPOINTS"
)
KNAME_RE: Final = re.compile(r"^[a-z0-9-]+$")
LSBLK_TIMEOUT: Final = 10.0

# lsblk spells each JSON key as the lowercased column name.
_KEYS: Final = tuple(column.lower() for column in LSBLK_COLUMNS.split(","))
_TEXT_KEYS: Final = frozenset({"kname", "path", "maj:min", "type"})
_BOOLEAN_KEYS: Final = frozenset({"hotplug", "rm", "ro"})
_SPECIAL_KEYS: Final = _TEXT_KEYS | _BOOLEAN_KEYS | {"size", "mountpoints"}
_ROOT_KEY: Final = "blockdevices"
_CHILDREN_KEY: Final = "children"
_CLASS_BLOCK: Final = "/sys/class/block"
_LIST_FAILED: Final = "cannot list block devices"
_INVALID_KNAME: Final = "invalid kernel device name"


@dataclass(frozen=True, slots=True)
class BlockDevice:
    kname: str
    path: str
    devnum: str  # "MAJ:MIN"
    type: str
    fstype: str | None
    label: str | None
    uuid: str | None
    partuuid: str | None
    pkname: str | None
    hotplug: bool
    ro: bool
    size: int  # bytes
    mountpoints: tuple[str, ...]
    tran: str | None


@dataclass(frozen=True, slots=True)
class DeviceTree:
    devices: Mapping[str, BlockDevice]  # by kname, in lsblk's order
    parents: Mapping[str, tuple[str, ...]]  # kname -> parent knames (tree form)

    def top_disk(self, kname: str) -> BlockDevice | None:
        """The device reached by following ``pkname`` up from ``kname``.

        None when ``kname`` or a link of the chain is unknown, or the chain
        loops.
        """
        seen: set[str] = set()
        device = self.devices.get(kname)
        while device is not None and device.pkname is not None:
            if device.kname in seen:
                return None
            seen.add(device.kname)
            device = self.devices.get(device.pkname)
        return device

    def is_removable(self, kname: str) -> bool | None:
        """``hotplug`` of the top disk; None (= internal) when it cannot be told."""
        top = self.top_disk(kname)
        return None if top is None else top.hotplug

    def by_uuid(self, uuid: str) -> tuple[BlockDevice, ...]:
        """Every device with ``uuid`` (any case), in lsblk's order."""
        wanted = uuid.lower()
        return tuple(
            device
            for device in self.devices.values()
            if device.uuid is not None and device.uuid.lower() == wanted
        )


def read_tree(ctx: "Context") -> DeviceTree:
    """One lsblk call; a failed or unreadable run raises ``ToolError``."""
    argv = (
        ctx.platform.tools.lsblk,
        "--json",
        "--bytes",
        "--tree",
        "-o",
        LSBLK_COLUMNS,
    )
    result = ctx.runner.run(Command(argv=argv, timeout=LSBLK_TIMEOUT))
    if result.returncode != 0:
        raise ToolError(
            _LIST_FAILED,
            detail=(
                f"lsblk: exit {result.returncode}, timed out {result.timed_out}, "
                f"not found {result.not_found}: {result.err_text().strip()}"
            ),
        )
    return parse_lsblk_json(result.stdout)


def parse_lsblk_json(data: bytes) -> DeviceTree:
    """The ``--json --bytes`` output, tree or list form, as a ``DeviceTree``.

    Bytes are decoded as UTF-8 with ``surrogateescape`` (DD-01), so a label
    byte that is not UTF-8 survives. A device nested under two parents is
    listed once, with both parents.
    """
    try:
        document = json.loads(data.decode("utf-8", TEXT_ERRORS))
    except ValueError as error:
        raise ToolError(_LIST_FAILED, detail=f"lsblk: not JSON: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get(_ROOT_KEY), list):
        raise ToolError(_LIST_FAILED, detail=f"lsblk: no {_ROOT_KEY!r} list")
    devices: dict[str, BlockDevice] = {}
    parents: dict[str, list[str]] = {}
    _collect(document[_ROOT_KEY], None, devices, parents)
    return DeviceTree(
        devices=MappingProxyType(devices),
        parents=MappingProxyType(
            {kname: tuple(found) for kname, found in parents.items()}
        ),
    )


def _collect(
    nodes: list[Any],
    parent: str | None,
    devices: dict[str, BlockDevice],
    parents: dict[str, list[str]],
) -> None:
    for node in nodes:
        device = _device(node)
        devices.setdefault(device.kname, device)
        found = parents.setdefault(device.kname, [])
        if parent is not None and parent not in found:
            found.append(parent)
        children = node.get(_CHILDREN_KEY, [])
        if not isinstance(children, list):
            raise ToolError(_LIST_FAILED, detail="lsblk: children is not a list")
        _collect(children, device.kname, devices, parents)


def _device(node: object) -> BlockDevice:
    if not isinstance(node, dict):
        raise ToolError(_LIST_FAILED, detail="lsblk: device is not an object")
    missing = [key for key in _KEYS if key not in node]
    if missing:
        raise ToolError(
            _LIST_FAILED, detail=f"lsblk output lacks columns {', '.join(missing)}"
        )
    for key in _TEXT_KEYS:
        _expect(node, key, str)
    for key in _BOOLEAN_KEYS:
        _expect(node, key, bool)
    for key in _KEYS:
        if key not in _SPECIAL_KEYS:
            _expect(node, key, str, nullable=True)
    return BlockDevice(
        kname=node["kname"],
        path=node["path"],
        devnum=node["maj:min"],
        type=node["type"],
        fstype=node["fstype"],
        label=node["label"],
        uuid=node["uuid"],
        partuuid=node["partuuid"],
        pkname=node["pkname"],
        hotplug=node["hotplug"],
        ro=node["ro"],
        size=_size(node["size"]),
        mountpoints=_mountpoints(node["mountpoints"]),
        tran=node["tran"],
    )


def _expect(
    node: dict[str, Any], key: str, kind: type, *, nullable: bool = False
) -> None:
    value = node[key]
    if value is None and nullable:
        return
    if not isinstance(value, kind):
        raise ToolError(
            _LIST_FAILED,
            detail=f"lsblk column {key}: expected {kind.__name__}, got {value!r}",
        )


def _size(value: object) -> int:
    # bool is an int subclass; a human size like "238.5G" means no --bytes.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolError(_LIST_FAILED, detail=f"lsblk size is not bytes: {value!r}")
    return value


def _mountpoints(value: object) -> tuple[str, ...]:
    # lsblk writes [null] for an unmounted device on some versions.
    if not isinstance(value, list) or not all(
        item is None or isinstance(item, str) for item in value
    ):
        raise ToolError(_LIST_FAILED, detail=f"lsblk mountpoints: {value!r}")
    return tuple(item for item in value if item is not None)


def validate_kname(kname: str) -> str:
    """``kname`` itself when it matches ``KNAME_RE`` (AC-030), else raise."""
    if KNAME_RE.fullmatch(kname) is None:
        raise InvalidKernelName(_INVALID_KNAME, detail=f"kname {kname!r}")
    return kname


def kname_of_syspath(syspath: str) -> str:
    """The validated last component of a ``/sys/devices/...`` path."""
    return validate_kname(syspath.rpartition("/")[2])


def slaves(ctx: "Context", kname: str) -> tuple[str, ...]:
    """Sorted entries of ``slaves/``; () when the device is absent."""
    return _listing(ctx, kname, "slaves")


def holders(ctx: "Context", kname: str) -> tuple[str, ...]:
    """Sorted entries of ``holders/``; () when the device is absent."""
    return _listing(ctx, kname, "holders")


def dm_name(ctx: "Context", kname: str) -> str | None:
    """``dm/name`` without its newline; None for a non-dm or absent device."""
    return _attribute(ctx, kname, "dm/name")


def devnum(ctx: "Context", kname: str) -> str | None:
    """``dev`` ("MAJ:MIN"); None when absent."""
    return _attribute(ctx, kname, "dev")


def syspath(ctx: "Context", kname: str) -> str | None:
    """The canonical sysfs directory as a host path; None when absent.

    A link that resolves outside the host root is treated as absent.
    """
    link = _device_dir(ctx, kname)
    if not link.exists():
        return None
    root = ctx.paths.root.resolve()
    resolved = link.resolve()
    if not resolved.is_relative_to(root):
        return None
    return "/" + resolved.relative_to(root).as_posix()


def _device_dir(ctx: "Context", kname: str) -> Path:
    return ctx.paths.p(f"{_CLASS_BLOCK}/{validate_kname(kname)}")


def _listing(ctx: "Context", kname: str, name: str) -> tuple[str, ...]:
    try:
        entries = os.listdir(_device_dir(ctx, kname) / name)
    except (FileNotFoundError, NotADirectoryError):
        return ()
    return tuple(sorted(entries))


def _attribute(ctx: "Context", kname: str, name: str) -> str | None:
    try:
        raw = (_device_dir(ctx, kname) / name).read_bytes()
    except (FileNotFoundError, NotADirectoryError):
        return None
    value = raw.decode("utf-8", TEXT_ERRORS).removesuffix("\n")
    return value or None
