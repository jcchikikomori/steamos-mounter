"""The registry ``/etc/steamos-mounter/config.toml``: read, validate, emit, save.

Design Doc "Registry (config.toml)", DD-07 and "Data Contracts > config.load";
ADR-0004 D3. The registry holds no secret, and the closed schema rejects any
unknown key, so a key cannot be added by hand either (AC-005).

Two levels of failure, kept apart on purpose:

- **Unusable** (``RegistryError``): the directory is missing, an owner, mode
  or symlink check fails, the text is not UTF-8 or TOML, a top-level key is
  unknown, or ``schema_version`` is not 1. Nothing mounts, auto-mounts
  included, because the auto path cannot know which UUIDs are registered.
- **Invalid entries** (``Registry.invalid``): one entry breaks a rule, or two
  entries clash (duplicate UUID, name or path, or nested paths). Those
  volumes do not mount, their valid UUIDs still block auto-mounting, and
  every other entry works.

An absent ``config.toml`` in a good directory is the empty registry: the
installer never creates it, the first ``add`` does (I001). ``save`` only
writes: ``add``, ``remove`` and the installer regenerate the wiring and
reload systemd right after it (Design Doc "Atomic Write" step 4).
"""

import logging
import os
import re
import tomllib
from collections.abc import Callable, Iterable, Mapping
from itertools import combinations
from typing import TYPE_CHECKING, Final, Literal

from steamos_mounter import locks
from steamos_mounter.atomicfile import check_owner_mode, write_atomic
from steamos_mounter.errors import RefusedError, RegistryError, UsageError
from steamos_mounter.model import InvalidEntry, Registry, Step, Volume
from steamos_mounter.naming import (
    REGISTRY_NAME_RE,
    PathKind,
    validate_fixed_path,
)
from steamos_mounter.ntfs import DRIVER_TOKENS, format_drivers, parse_drivers

if TYPE_CHECKING:
    from pathlib import Path

    from steamos_mounter.context import Context

REGISTRY_DIR: Final = "/etc/steamos-mounter"
REGISTRY_PATH: Final = f"{REGISTRY_DIR}/config.toml"
SCHEMA_VERSION: Final = 1
REGISTRY_MODE: Final = 0o644
# Neither the file nor its directory may be writable by group or others.
FORBIDDEN_BITS: Final = 0o022
HEADER: Final = (
    "# steamos-mounter registry. "
    "Managed by steamos-mounter: comments and formatting are not kept."
)
UNUSABLE: Final = "the registry cannot be used"

TOP_LEVEL_KEYS: Final = frozenset({"schema_version", "volume"})
FSTYPES: Final = frozenset({"ntfs", "exfat", "vfat", "btrfs", "BitLocker"})  # DD-07
DRIVERS_FSTYPES: Final = frozenset({"ntfs", "BitLocker"})
UUID_FORMS: Final = (
    re.compile(r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}"),  # FAT, exFAT
    re.compile(r"[0-9A-Fa-f]{16}"),  # NTFS
    re.compile(  # RFC 4122 (btrfs, the BitLocker container)
        r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
    ),
)
DUPLICATE_UUID: Final = "duplicate uuid"
DUPLICATE_NAME: Final = "duplicate name"
DUPLICATE_PATH: Final = "duplicate path"
NESTED_PATH: Final = "path nested with another entry's path"
# Without a platform at hand only the fixed /run/media rule applies; naming
# refuses /run/media and its parents anyway, so this adds no rule of its own.
NO_MOUNT_BASE: Final = "/run/media"
# A TOML control character: U+0000 to U+001F and U+007F.
_TOML_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")
_TOML_ESCAPES: Final = {"\\": "\\\\", '"': '\\"'}

log = logging.getLogger(__name__)


# --- reading --------------------------------------------------------------------------


def load(ctx: "Context") -> Registry:
    """Owner and mode checks, then ``parse`` with the platform's mount base.

    Raises ``RegistryError`` when the registry is unusable. An absent file in
    a good directory is the empty registry.
    """
    uid = ctx.platform.trusted_uid
    directory = ctx.paths.p(REGISTRY_DIR)
    if not os.path.lexists(directory):
        raise _unusable(f"{REGISTRY_DIR} is missing: install has not run")
    _require_trusted(directory, REGISTRY_DIR, uid=uid, kind="dir")
    path = ctx.paths.p(REGISTRY_PATH)
    if not os.path.lexists(path):
        return Registry(schema_version=SCHEMA_VERSION, volumes=(), invalid=())
    _require_trusted(path, REGISTRY_PATH, uid=uid, kind="file")
    try:
        text = _read(path).decode("utf-8")
    except UnicodeDecodeError as error:
        raise _unusable(f"{REGISTRY_PATH}: not valid UTF-8") from error
    try:
        return parse(text, mount_base=ctx.platform.mount_base)
    except RegistryError as error:
        raise _unusable(f"{REGISTRY_PATH}: {error.detail}") from error


def parse(text: str, *, mount_base: str | None = None) -> Registry:
    """Validate registry ``text``; ``RegistryError`` when it is unusable.

    ``mount_base`` is the platform's: a path equal to it, or one of its
    parents, is invalid. ``load`` always passes it. Disk facts of the fixed
    path rules (an existing non-empty directory, a missing parent) are not
    checked here; ``add`` and every mount check them.
    """
    entries = _entries(_toml(text))
    base = mount_base or NO_MOUNT_BASE
    candidates: list[tuple[int, Volume]] = []
    invalid: list[InvalidEntry] = []
    for index, entry in enumerate(entries):
        problem = _entry_problem(entry, base)
        if problem is None:
            candidates.append((index, _volume(entry)))
        else:
            invalid.append(InvalidEntry(index, _valid_uuid(entry), problem))
    clashes = _clashes(candidates)
    invalid.extend(
        InvalidEntry(index, volume.uuid, clashes[index])
        for index, volume in candidates
        if index in clashes
    )
    return Registry(
        schema_version=SCHEMA_VERSION,
        volumes=tuple(volume for index, volume in candidates if index not in clashes),
        invalid=tuple(sorted(invalid, key=_entry_index)),
    )


def _require_trusted(
    path: "Path", logical: str, *, uid: int, kind: Literal["file", "dir"]
) -> None:
    problem = check_owner_mode(path, uid=uid, forbid=FORBIDDEN_BITS, kind=kind)
    if problem is not None:
        raise _unusable(f"{logical}: {problem.problem}")


def _read(path: "Path") -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise _unusable(f"{REGISTRY_PATH}: cannot be read: {error.strerror}") from error
    with os.fdopen(fd, "rb") as stream:
        return stream.read()


def _unusable(reason: str) -> RegistryError:
    return RegistryError(UNUSABLE, detail=reason)


def _toml(text: str) -> dict[str, object]:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise _unusable(f"not valid TOML: {error}") from error


def _entries(document: Mapping[str, object]) -> list[object]:
    """Top-level rules; the raw ``[[volume]]`` entries."""
    unknown = next((key for key in document if key not in TOP_LEVEL_KEYS), None)
    if unknown is not None:
        raise _unusable(f"unknown top-level key {unknown!r}")
    if "schema_version" not in document:
        raise _unusable("schema_version is missing")
    version = document["schema_version"]
    # bool is an int, and 1.0 == 1: both are refused.
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise _unusable("schema_version is not 1")
    entries = document.get("volume", [])
    if not isinstance(entries, list):
        raise _unusable("volume is not an array of tables")
    return entries


def _entry_index(entry: InvalidEntry) -> int:
    return entry.index


# --- per-entry rules (one row per key) ------------------------------------------------

Check = Callable[[object, str], str | None]


def _check_name(value: object, _mount_base: str) -> str | None:
    if not isinstance(value, str):
        return "name: must be a string"
    if REGISTRY_NAME_RE.fullmatch(value) is None:
        return "name: not a valid registry name"
    return None


def _is_uuid(value: str) -> bool:
    return any(form.fullmatch(value) for form in UUID_FORMS)


def _check_uuid(value: object, _mount_base: str) -> str | None:
    if not isinstance(value, str):
        return "uuid: must be a string"
    if not _is_uuid(value):
        return "uuid: not a valid UUID"
    return None


class _AssumeFree:
    """``PathFacts`` that skips the disk: every path is an empty directory,
    and every parent a trusted one."""

    def kind(self, path: str) -> PathKind:
        return PathKind.EMPTY_DIR

    def trusted_dir(self, path: str) -> bool:
        return True


def _check_path(value: object, mount_base: str) -> str | None:
    """The static part of the fixed-path rules (syntax and location)."""
    if not isinstance(value, str):
        return "path: must be a string"
    try:
        validate_fixed_path(
            value, mount_base=mount_base, other_paths=(), fs=_AssumeFree()
        )
    except RefusedError as refused:
        return refused.user_message
    return None


def _check_fstype(value: object, _mount_base: str) -> str | None:
    if not isinstance(value, str):
        return "fstype: must be a string"
    if value not in FSTYPES:
        return "fstype: not a supported filesystem type"
    return None


def _check_drivers(value: object, _mount_base: str) -> str | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return "drivers: must be a list of strings"
    if not value:
        return "drivers: must not be empty"
    if any(token not in DRIVER_TOKENS for token in value):
        return "drivers: unknown token"
    if len(set(value)) != len(value):
        return "drivers: duplicate token"
    return None


def _flag_check(key: str) -> Check:
    def check(value: object, _mount_base: str) -> str | None:
        return None if isinstance(value, bool) else f"{key}: must be a boolean"

    return check


# (key, required, check), in the emitter's key order.
RULES: Final[tuple[tuple[str, bool, Check], ...]] = (
    ("name", True, _check_name),
    ("uuid", True, _check_uuid),
    ("path", True, _check_path),
    ("fstype", True, _check_fstype),
    ("drivers", False, _check_drivers),
    ("nosuid", False, _flag_check("nosuid")),
    ("nodev", False, _flag_check("nodev")),
)
ENTRY_KEYS: Final = frozenset(key for key, _required, _check in RULES)


def _entry_problem(entry: object, mount_base: str) -> str | None:
    """The first rule ``entry`` breaks, in words that never quote a value."""
    if not isinstance(entry, dict):
        return "entry is not a table"
    unknown = next((key for key in entry if key not in ENTRY_KEYS), None)
    if unknown is not None:
        return f"unknown key {unknown!r}"
    for key, required, check in RULES:
        if key in entry:
            problem = check(entry[key], mount_base)
        else:
            problem = f"missing key {key!r}" if required else None
        if problem is not None:
            return problem
    if "drivers" in entry and entry["fstype"] not in DRIVERS_FSTYPES:
        return "drivers: only for ntfs or BitLocker"
    return None


def _valid_uuid(entry: object) -> str | None:
    """The entry's UUID when it is one: it still blocks auto-mounting."""
    if not isinstance(entry, dict):
        return None
    uuid = entry.get("uuid")
    return uuid if isinstance(uuid, str) and _is_uuid(uuid) else None


def _volume(entry: Mapping[str, object]) -> Volume:
    """A ``Volume`` from an entry that passed ``_entry_problem``."""
    return Volume(
        name=str(entry["name"]),
        uuid=str(entry["uuid"]),
        path=str(entry["path"]),
        fstype=str(entry["fstype"]),
        drivers=_steps(entry.get("drivers")),
        nosuid=bool(entry.get("nosuid", True)),
        nodev=bool(entry.get("nodev", True)),
    )


def _steps(tokens: object) -> tuple[Step, ...] | None:
    if not isinstance(tokens, list):
        return None
    return parse_drivers(tokens)


# --- cross-entry rules ----------------------------------------------------------------


def _inside(path: str, other: str) -> bool:
    return path.startswith(other.rstrip("/") + "/")


def _clash(first: Volume, second: Volume) -> str | None:
    """Why two volumes cannot both be registered, or ``None``."""
    if first.uuid.lower() == second.uuid.lower():
        return DUPLICATE_UUID
    if first.name.casefold() == second.name.casefold():
        return DUPLICATE_NAME
    if first.path == second.path:
        return DUPLICATE_PATH
    if _inside(first.path, second.path) or _inside(second.path, first.path):
        return NESTED_PATH
    return None


def _clashes(candidates: Iterable[tuple[int, Volume]]) -> dict[int, str]:
    """Entry index -> reason, for every entry involved in a clash."""
    reasons: dict[int, str] = {}
    for (first_index, first), (second_index, second) in combinations(candidates, 2):
        reason = _clash(first, second)
        if reason is not None:
            reasons.setdefault(first_index, reason)
            reasons.setdefault(second_index, reason)
    return reasons


# --- changing -------------------------------------------------------------------------


def with_volume(registry: Registry, volume: Volume) -> Registry:
    """``registry`` plus ``volume``, sorted by name.

    Raises ``RefusedError`` when ``volume`` breaks a rule a read would apply,
    or clashes with a registered volume (duplicate UUID, name or path, or
    nesting). Invalid entries are carried along unchanged.
    """
    problem = _entry_problem(_fields(volume), NO_MOUNT_BASE)
    if problem is not None:
        raise RefusedError(problem, detail=f"registry entry refused: {problem}")
    for registered in registry.volumes:
        reason = _clash(volume, registered)
        if reason is not None:
            raise RefusedError(
                reason,
                detail=f"registry entry clashes with {registered.name}: {reason}",
            )
    return Registry(
        schema_version=registry.schema_version,
        volumes=tuple(sorted((*registry.volumes, volume), key=_volume_name)),
        invalid=registry.invalid,
    )


def without_volume(registry: Registry, name: str) -> Registry:
    """``registry`` without the volume called ``name`` (any case).

    Raises ``UsageError`` when no volume has that name.
    """
    removed = registry.by_name(name)
    if removed is None:
        raise UsageError(f"no registered volume is called {name}")
    return Registry(
        schema_version=registry.schema_version,
        volumes=tuple(volume for volume in registry.volumes if volume is not removed),
        invalid=registry.invalid,
    )


def save(ctx: "Context", registry: Registry) -> None:
    """Write ``registry`` under the registry lock, atomically, root 0644.

    The current file is read and validated first: an unusable registry is
    never replaced, so a broken hand edit is not lost (``RegistryError``,
    exit 1). An absent file counts as empty, so the first ``add`` creates it.
    Invalid entries are not written. Callers wire and reload afterwards.
    """
    with locks.registry_lock(ctx):
        load(ctx)
        write_atomic(
            ctx.paths.p(REGISTRY_PATH),
            emit(registry).encode("utf-8"),
            mode=REGISTRY_MODE,
            uid=ctx.platform.trusted_uid,
            # Root entries run with group 0, which gives the Design Doc's
            # root:root; the group carries no trust (mode 0644).
            gid=os.getegid(),
        )
    log.info("registry saved with %d volumes", len(registry.volumes))


# --- emitting -------------------------------------------------------------------------


def emit(registry: Registry) -> str:
    """The registry in the Design Doc's exact shape, volumes sorted by name.

    Header, ``schema_version = 1``, then one ``[[volume]]`` table per volume
    after a blank line; keys in schema order, ``drivers`` only when set.
    Invalid entries are not part of the output.
    """
    head = f"{HEADER}\nschema_version = {SCHEMA_VERSION}\n"
    tables = [_table(volume) for volume in sorted(registry.volumes, key=_volume_name)]
    return "\n".join([head, *tables])


def _volume_name(volume: Volume) -> str:
    return volume.name


def _fields(volume: Volume) -> dict[str, object]:
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
        f"{key} = {_toml_value(value)}" for key, value in _fields(volume).items()
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
