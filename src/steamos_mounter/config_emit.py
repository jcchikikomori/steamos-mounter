"""The registry emitter: ``config.toml`` text in the Design Doc's exact shape.

Design Doc "Registry (config.toml) > Emitter". Split from ``config`` (which
re-exports ``emit``, ``HEADER`` and ``SCHEMA_VERSION``) so each module stays
small; it holds no I/O. ``volume_fields`` is also the table ``config`` checks
a new entry against before it is added.
"""

import re
from typing import Final

from steamos_mounter.model import Registry, Volume
from steamos_mounter.ntfs import format_drivers

SCHEMA_VERSION: Final = 1
HEADER: Final = (
    "# steamos-mounter registry. "
    "Managed by steamos-mounter: comments and formatting are not kept."
)
# A TOML control character: U+0000 to U+001F and U+007F.
_TOML_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")
_TOML_ESCAPES: Final = {"\\": "\\\\", '"': '\\"'}


def emit(registry: Registry) -> str:
    """The registry in the Design Doc's exact shape, volumes sorted by name.

    Header, ``schema_version = 1``, then one ``[[volume]]`` table per volume
    after a blank line; keys in schema order, ``drivers`` only when set.
    Invalid entries are not part of the output.
    """
    head = f"{HEADER}\nschema_version = {SCHEMA_VERSION}\n"
    tables = [_table(volume) for volume in sorted(registry.volumes, key=volume_name)]
    return "\n".join([head, *tables])


def volume_name(volume: Volume) -> str:
    return volume.name


def volume_fields(volume: Volume) -> dict[str, object]:
    """``volume`` as its table's keys and values, in schema order."""
    fields: dict[str, object] = {
        "name": volume.name,
        "uuid": volume.uuid,
        "path": volume.path,
        "fstype": volume.fstype,
    }
    if volume.drivers is not None:
        fields["drivers"] = format_drivers(volume.drivers)
    fields["nosuid"] = volume.nosuid
    fields["nodev"] = volume.nodev
    return fields


def _table(volume: Volume) -> str:
    lines = ["[[volume]]"]
    lines.extend(
        f"{key} = {_toml_value(value)}" for key, value in volume_fields(volume).items()
    )
    return "\n".join(lines) + "\n"


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    return _toml_string(str(value))


def _toml_string(value: str) -> str:
    """A TOML basic string: ``\\\\``, ``\\"`` and ``\\uXXXX`` for controls."""
    escaped = "".join(_TOML_ESCAPES.get(char, char) for char in value)
    return '"' + _TOML_CONTROL.sub(_unicode_escape, escaped) + '"'


def _unicode_escape(match: re.Match[str]) -> str:
    return f"\\u{ord(match.group()):04X}"
