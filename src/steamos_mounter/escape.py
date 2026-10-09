"""systemd path escaping and unit names for the instance units.

Design Doc "blockdev, mounts, naming, escape" and Fact
"systemd-escape:instance-naming"; ADR-0002 D1. Instance names are built only
from the by-uuid path or the sysfs path, never from labels, and must match
``systemd-escape --path`` byte for byte, or the tool would address a different
unit than the one udev started. ``tests/contract/test_escape.py`` holds the
Deck's real outputs.

The rules mirror systemd's ``unit_name_path_escape``: empty and ``.``
components are dropped and the root becomes ``-``; every UTF-8 byte outside
``[A-Za-z0-9:_.]``, plus a leading ``.``, becomes ``\\xNN``; ``/`` becomes
``-``. Two deliberate differences, both refusals: a relative path (instances
always come from absolute paths, and ``unescape_path`` always returns one) and
a NUL character (systemd would silently cut the string there).

systemd refuses a unit name whose length is ``UNIT_NAME_MAX`` or more
(``strlen(name) >= UNIT_NAME_MAX`` in ``unit_name_is_valid``), so the longest
usable name is 255 characters.
"""

import re
import string
from typing import Final

UNIT_NAME_MAX: Final = 256
BY_UUID_DIR: Final = "/dev/disk/by-uuid/"
SERVICE_SUFFIX: Final = ".service"

# Bytes systemd keeps as they are; "-" and "\\" are always escaped.
_PLAIN_BYTES: Final = frozenset(
    (string.ascii_letters + string.digits + ":_.").encode("ascii")
)
_SLASH: Final = ord("/")
_DOT: Final = ord(".")
_HEX_ESCAPE: Final = re.compile(rb"\\x([0-9A-Fa-f]{2})")
_TEXT_ERRORS: Final = "surrogateescape"  # undecodable path bytes survive (DD-01)


def _escape_byte(byte: int) -> bytes:
    return b"\\x%02x" % byte


def _escape_component_bytes(data: bytes) -> str:
    """systemd's ``do_escape`` over ``data`` with ``/`` already joined in."""
    out = bytearray()
    for index, byte in enumerate(data):
        if byte == _SLASH:
            out += b"-"
        elif byte in _PLAIN_BYTES and not (index == 0 and byte == _DOT):
            out.append(byte)
        else:
            out += _escape_byte(byte)
    return out.decode("ascii")


def escape_path(path: str) -> str:
    """Escape an absolute path exactly as ``systemd-escape --path`` does.

    Raises ``ValueError`` for a relative path, a NUL, or a ``..`` component.
    """
    if not path.startswith("/") or "\x00" in path:
        raise ValueError(f"cannot escape path {path!r}: not an absolute path")
    components = [part for part in path.split("/") if part not in ("", ".")]
    if ".." in components:
        raise ValueError(f"cannot escape path {path!r}: it has a '..' component")
    if not components:
        return "-"
    return _escape_component_bytes("/".join(components).encode("utf-8", _TEXT_ERRORS))


def _unescape_bytes(escaped: str) -> bytes:
    data = escaped.encode("utf-8", _TEXT_ERRORS)
    out = bytearray()
    position = 0
    while position < len(data):
        byte = data[position]
        if byte == ord("-"):
            out.append(_SLASH)
            position += 1
        elif byte == ord("\\"):
            match = _HEX_ESCAPE.match(data, position)
            if match is None:
                raise ValueError(f"cannot unescape {escaped!r}: bad escape sequence")
            out.append(int(match[1], 16))
            position = match.end()
        else:
            out.append(byte)
            position += 1
    return bytes(out)


def unescape_path(escaped: str) -> str:
    """Invert ``escape_path`` as ``systemd-escape --unescape --path`` does.

    Raises ``ValueError`` for an empty string, a bad ``\\`` sequence, a NUL,
    or a result that is not a normalized absolute path.
    """
    if escaped == "-":
        return "/"
    if not escaped:
        raise ValueError("cannot unescape an empty name")
    relative = _unescape_bytes(escaped).decode("utf-8", _TEXT_ERRORS)
    components = relative.split("/")
    if "\x00" in relative or any(part in ("", ".", "..") for part in components):
        raise ValueError(f"cannot unescape {escaped!r}: not a normalized path")
    return "/" + relative


def registered_instance(uuid: str) -> str:
    """Instance name of the registered unit: the escaped by-uuid path."""
    if uuid in ("", ".", "..") or "/" in uuid:
        raise ValueError(f"uuid {uuid!r} is not a single path component")
    return escape_path(BY_UUID_DIR + uuid)


def auto_instance(syspath: str) -> str:
    """Instance name of the auto unit: the escaped sysfs path."""
    return escape_path(syspath)


def unit_name(template: str, instance: str) -> str:
    """``<template><instance>.service``; ``template`` ends with ``@``.

    Raises ``ValueError`` when the name would reach ``UNIT_NAME_MAX``
    characters, which systemd refuses (ADR-0002 D1).
    """
    prefix = template.removesuffix("@")
    if not prefix or prefix == template:
        raise ValueError(f"unit template {template!r} must be '<prefix>@'")
    if not instance:
        raise ValueError("unit instance must not be empty")
    name = f"{template}{instance}{SERVICE_SUFFIX}"
    if len(name) >= UNIT_NAME_MAX:
        raise ValueError(
            f"unit name of {len(name)} characters reaches systemd's limit of"
            f" {UNIT_NAME_MAX}"
        )
    return name
