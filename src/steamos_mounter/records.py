"""Runtime records: the ``/run`` tree and one JSON record per owning instance.

Design Doc "Runtime State Records" (D002, Record Schema (Format 1), Write
Rules) and DD-10.

- **Runtime tree** (D002): ``/run`` is tmpfs, so every root entry recreates
  ``RUNTIME_DIRS`` parent first, before its first lock or record. Each
  directory is created when missing, then checked with ``lstat`` (a real
  directory owned by ``trusted_uid``), then set to its manifest mode through
  a descriptor opened with ``O_NOFOLLOW``, so the caller's umask cannot narrow
  it and a symlink is never followed. Any problem fails closed with
  ``MounterError``. Non-root entries create nothing and read a missing tree
  as "no records".
- **Records** (DD-10): one JSON file per owning instance, written whole and
  atomically (root 0644) through ``update_record``, whose caller holds the
  per-volume lock. ``update_record`` cannot take that lock itself: ``flock``
  conflicts between two descriptors of one process, and the lock key of an
  auto volume is not its record key (I007). A record that breaks the schema
  is ``"unreadable"``; nested objects are kept as plain JSON objects.
"""

import contextlib
import copy
import errno
import json
import logging
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, Literal

from steamos_mounter.atomicfile import check_owner_mode, write_atomic
from steamos_mounter.errors import MounterError
from steamos_mounter.locks import VOLUME_KEY
from steamos_mounter.model import InstanceKind, Trigger, VolumeState

if TYPE_CHECKING:
    from steamos_mounter.context import Context

RECORD_FORMAT: Final = 1
RUNTIME_DIRS: Final = (  # must equal the manifest's /run rows (contract test)
    ("/run/steamos-mounter", 0o755),
    ("/run/steamos-mounter/records", 0o755),
    ("/run/steamos-mounter/records/registered", 0o755),
    ("/run/steamos-mounter/records/auto", 0o755),
    ("/run/steamos-mounter/locks", 0o700),
)
RECORDS_DIR: Final = "/run/steamos-mounter/records"
RECORD_SUFFIX: Final = ".json"
RECORD_MODE: Final = 0o644
UNREADABLE: Final = "unreadable"
TIMESTAMP_FORMAT: Final = "%Y-%m-%dT%H:%M:%SZ"
UNTRUSTED_TREE: Final = "the runtime state directory cannot be trusted: run doctor"

_DIR_OPEN_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# O_NONBLOCK: a FIFO planted in place of a record cannot hang the reader.
_RECORD_OPEN_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK

log = logging.getLogger(__name__)


# --- runtime tree (D002) --------------------------------------------------------------


def ensure_runtime_dirs(ctx: "Context") -> None:
    """Create and check the ``/run/steamos-mounter`` tree; root only.

    Raises ``MounterError`` (exit 1, "run doctor") when a directory cannot be
    created, is a symlink or not a directory, or is owned by anyone but
    ``trusted_uid``. Directories after the failing one are not touched.
    """
    if ctx.euid != 0:
        return
    for absolute, mode in RUNTIME_DIRS:
        _ensure_dir(ctx, absolute, mode)


def _ensure_dir(ctx: "Context", absolute: str, mode: int) -> None:
    path = ctx.paths.p(absolute)
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        pass
    except OSError as error:
        raise _untrusted(f"{absolute}: cannot be created: {error.strerror}") from error
    problem = check_owner_mode(path, uid=ctx.platform.trusted_uid, forbid=0, kind="dir")
    if problem is not None:
        raise _untrusted(f"{absolute}: {problem.problem}")
    try:
        fd = os.open(path, _DIR_OPEN_FLAGS)
        try:
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    except OSError as error:
        raise _untrusted(f"{absolute}: mode not set: {error.strerror}") from error


def _untrusted(detail: str) -> MounterError:
    return MounterError(UNTRUSTED_TREE, detail=detail)


# --- records (format 1) ---------------------------------------------------------------


def _is_format(value: object) -> bool:
    return type(value) is int and value == RECORD_FORMAT


def _is_text(value: object) -> bool:
    return isinstance(value, str)


def _is_optional_text(value: object) -> bool:
    return value is None or isinstance(value, str)


def _is_object(value: object) -> bool:
    return isinstance(value, dict)


def _is_optional_object(value: object) -> bool:
    return value is None or isinstance(value, dict)


def _is_text_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


# The Design Doc's Record Schema (Format 1), field by field, in its order.
_FIELD_CHECKS: Final[Mapping[str, Callable[[object], bool]]] = MappingProxyType(
    {
        "format": _is_format,
        "kind": _is_text,
        "key": _is_text,
        "name": _is_text,
        "unit": _is_text,
        "invocation_id": _is_text,
        "state": _is_text,
        "reason": _is_optional_text,
        "warning": _is_optional_text,
        "next_step": _is_optional_text,
        "updated_at": _is_text,
        "trigger": _is_text,
        "source": _is_optional_object,
        "mapping": _is_optional_object,
        "mount": _is_optional_object,
        "attempt": _is_object,
        "unmounted_by_user": _is_optional_object,
        "cli_request": _is_optional_object,
        "dialog": _is_object,
        "service": _is_object,
        "busy": _is_text_list,
    }
)
RECORD_FIELDS: Final = tuple(_FIELD_CHECKS)


@dataclass(slots=True, kw_only=True)
class Record:
    """One runtime record. Nested objects are the schema's JSON objects."""

    format: int
    kind: InstanceKind
    key: str
    name: str
    unit: str
    invocation_id: str
    state: VolumeState
    reason: str | None
    warning: str | None
    next_step: str | None
    updated_at: str
    trigger: Trigger
    source: dict[str, Any] | None
    mapping: dict[str, Any] | None
    mount: dict[str, Any] | None
    attempt: dict[str, Any]
    unmounted_by_user: dict[str, Any] | None
    cli_request: dict[str, Any] | None
    dialog: dict[str, Any]
    service: dict[str, Any]
    busy: list[str]

    @classmethod
    def empty(
        cls,
        kind: InstanceKind,
        key: str,
        *,
        invocation_id: str | None,
        updated_at: str,
    ) -> "Record":
        """A record that owns nothing yet: no source, mapping or mount."""
        return cls(
            format=RECORD_FORMAT,
            kind=kind,
            key=key,
            name="",
            unit="",
            invocation_id=invocation_id or "",
            state=VolumeState.NOT_MOUNTED,
            reason=None,
            warning=None,
            next_step=None,
            updated_at=updated_at,
            trigger=Trigger.START,
            source=None,
            mapping=None,
            mount=None,
            attempt={"probe": None, "steps": [], "skipped": []},
            unmounted_by_user=None,
            cli_request=None,
            dialog={"outcome": None, "at": None},
            service={
                "result": None,
                "exit_code": None,
                "exit_status": None,
                "at": None,
            },
            busy=[],
        )

    @classmethod
    def from_dict(cls, data: object) -> "Record":
        """Validate ``data`` against the schema; ``ValueError`` when it breaks it."""
        if not isinstance(data, dict) or set(data) != set(RECORD_FIELDS):
            raise ValueError("record fields differ from format 1")
        broken = [
            name for name, check in _FIELD_CHECKS.items() if not check(data[name])
        ]
        if broken:
            raise ValueError(f"record fields of the wrong type: {', '.join(broken)}")
        values = copy.deepcopy(data)
        values["kind"] = InstanceKind(values["kind"])
        values["state"] = VolumeState(values["state"])
        values["trigger"] = Trigger(values["trigger"])
        return cls(**values)

    def to_dict(self) -> dict[str, Any]:
        """The record as schema JSON; ``ValueError`` for an unknown enum value."""
        data = {name: copy.deepcopy(getattr(self, name)) for name in RECORD_FIELDS}
        data["kind"] = InstanceKind(self.kind).value
        data["state"] = VolumeState(self.state).value
        data["trigger"] = Trigger(self.trigger).value
        return data


def record_path(ctx: "Context", kind: InstanceKind, key: str) -> Path:
    """``records/<kind>/<key lowercased>.json`` under the host root.

    ``key`` is the registry UUID or ``<kname>-<major>_<minor>`` (I007);
    anything that is not a safe file name raises ``ValueError``.
    """
    lowered = key.lower()
    if VOLUME_KEY.fullmatch(lowered) is None:
        raise ValueError(f"not a record key: {key!r}")
    return ctx.paths.p(f"{RECORDS_DIR}/{InstanceKind(kind).value}/{lowered}.json")


def load_record(
    ctx: "Context", kind: InstanceKind, key: str
) -> Record | Literal["unreadable"] | None:
    """The record, None when there is none, ``"unreadable"`` when it is broken.

    Broken means: not a regular file (a symlink is not followed), not UTF-8
    JSON, not format 1, or naming another kind or key than its path.
    """
    path = record_path(ctx, kind, key)
    try:
        raw = _read_regular(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        return _unreadable(path, error.strerror or str(error))
    try:
        record = Record.from_dict(json.loads(raw.decode("utf-8")))
    except ValueError as error:
        return _unreadable(path, str(error))
    if record.kind is not InstanceKind(kind) or record.key != key.lower():
        return _unreadable(path, "kind or key differs from the file name")
    return record


def update_record(
    ctx: "Context", kind: InstanceKind, key: str, change: Callable[[Record], None]
) -> Record:
    """Read, apply ``change``, stamp ``updated_at`` and write atomically (0644).

    The caller holds the per-volume lock (Write Rules item 1). A missing or
    unreadable record starts from ``Record.empty``. ``change`` may not alter
    ``format``, ``kind`` or ``key`` (``ValueError``, nothing written).
    """
    lowered = key.lower()
    path = record_path(ctx, kind, lowered)
    stamp = _timestamp(ctx)
    current = load_record(ctx, kind, lowered)
    if isinstance(current, Record):
        record = current
    else:
        if current == UNREADABLE:
            log.warning("replacing the unreadable record %s", path.name)
        record = Record.empty(
            InstanceKind(kind),
            lowered,
            invocation_id=ctx.invocation_id,
            updated_at=stamp,
        )
    change(record)
    if (record.format, record.kind, record.key) != (RECORD_FORMAT, kind, lowered):
        raise ValueError("a record change may not alter format, kind or key")
    record.updated_at = stamp
    data = Record.from_dict(record.to_dict()).to_dict()
    write_atomic(
        path,
        (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode("ascii"),
        mode=RECORD_MODE,
        uid=ctx.platform.trusted_uid,
        # Root entries run with group 0, which gives root:root; the group
        # carries no trust (mode 0644).
        gid=os.getegid(),
    )
    return record


def delete_record(ctx: "Context", kind: InstanceKind, key: str) -> None:
    """Remove the record; a missing one is fine. The caller holds the lock."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(record_path(ctx, kind, key))


def _read_regular(path: Path) -> bytes:
    fd = os.open(path, _RECORD_OPEN_FLAGS)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        return stream.read()


def _unreadable(path: Path, why: str) -> Literal["unreadable"]:
    log.warning("record %s is unreadable: %s", path.name, why)
    return UNREADABLE


def _timestamp(ctx: "Context") -> str:
    return ctx.clock.now().astimezone(UTC).strftime(TIMESTAMP_FORMAT)
