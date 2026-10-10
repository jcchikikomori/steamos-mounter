"""Install manifest: the release's ``data/manifest.tsv``, format 1.

Design Doc "Install Manifest (Authoritative)". One record per line; lines
starting with ``#`` are comments; the first record is ``format 1``. Each other
record has six fields (``kind``, ``path``, ``owner``, ``mode``, ``source``,
``role``), split on any run of spaces or tabs, the same as ``uninstall.sh``
reading it with the default ``IFS``. The shipped file uses single tabs.

Install, uninstall and doctor read it, so ``parse`` accepts only what those
readers can act on and refuses anything else with ``MounterError``: a generic
message for the terminal, the line number and reason in ``detail`` for the
journal. doctor reports a refusal as "cannot verify" (the tripwire).
"""

import posixpath
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal, cast, get_args

from steamos_mounter.errors import MounterError

Kind = Literal["dir", "file", "registry", "link"]

KINDS: Final = frozenset(get_args(Kind))
FORMAT_RECORD: Final = ("format", "1")
FIELD_COUNT: Final = 6
COMMENT: Final = "#"
NO_VALUE: Final = "-"
ETC_PREFIX: Final = "/etc/"
ETC_KINDS: Final = frozenset({"file", "registry"})
UNUSABLE: Final = "the install manifest is unusable"
# Kinds whose mode column must be "-", and kinds whose source column must be.
MODELESS_KINDS: Final = frozenset({"link"})
SOURCELESS_KINDS: Final = frozenset({"dir", "registry"})
SOURCE_REQUIRED_KINDS: Final = frozenset({"file"})
PARENT_COMPONENT: Final = ".."

_MODE: Final = re.compile(r"0[0-7]{3}")
_OWNER: Final = re.compile(r"[a-z_][a-z0-9_-]*:[a-z_][a-z0-9_-]*")


@dataclass(frozen=True, slots=True)
class Entry:
    """One manifest record; unset: ``mode`` is ``None``, ``source`` is ``"-"``."""

    kind: Kind
    path: str
    owner: str
    mode: int | None
    source: str
    role: str


def parse(text: str) -> tuple[Entry, ...]:
    """Every record of a format 1 manifest, in file order.

    Raises ``MounterError`` when the format line is missing or not ``format
    1``, a record is blank or has the wrong field count, a field is invalid
    for its kind, or a path appears twice.
    """
    entries: list[Entry] = []
    seen_format = False
    paths: set[str] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        if line.startswith(COMMENT):
            continue
        fields = tuple(line.split())
        if not seen_format:
            if fields != FORMAT_RECORD:
                raise _unusable(number, f"unsupported format: {' '.join(fields)!r}")
            seen_format = True
            continue
        entry = _entry(number, fields)
        if entry.path in paths:
            raise _unusable(number, f"duplicate path: {entry.path!r}")
        paths.add(entry.path)
        entries.append(entry)
    if not seen_format:
        raise MounterError(UNUSABLE, detail="no format line")
    return tuple(entries)


def etc_paths(entries: Sequence[Entry]) -> tuple[str, ...]:
    """Paths of the ``file`` and ``registry`` rows under ``/etc/``, in order.

    These are the manifest's half of doctor's keep-list expected set.
    """
    return tuple(
        entry.path
        for entry in entries
        if entry.kind in ETC_KINDS and entry.path.startswith(ETC_PREFIX)
    )


def _entry(number: int, fields: tuple[str, ...]) -> Entry:
    if not fields:
        raise _unusable(number, "blank line")
    if len(fields) != FIELD_COUNT:
        raise _unusable(number, f"expected {FIELD_COUNT} fields, found {len(fields)}")
    kind, path, owner, mode, source, role = fields
    problem = (
        _kind_problem(kind)
        or _path_problem(path)
        or _owner_problem(owner)
        or _mode_problem(kind, mode)
        or _source_problem(kind, source)
    )
    if problem is not None:
        raise _unusable(number, problem)
    return Entry(
        cast("Kind", kind),
        path,
        owner,
        None if mode == NO_VALUE else int(mode, 8),
        source,
        role,
    )


def _kind_problem(kind: str) -> str | None:
    return None if kind in KINDS else f"unknown kind: {kind!r}"


def _path_problem(path: str) -> str | None:
    if path.startswith("/") and posixpath.normpath(path) == path:
        return None
    return f"path is not absolute and normal: {path!r}"


def _owner_problem(owner: str) -> str | None:
    return None if _OWNER.fullmatch(owner) else f"bad owner: {owner!r}"


def _mode_problem(kind: str, mode: str) -> str | None:
    if kind in MODELESS_KINDS:
        return None if mode == NO_VALUE else f"{kind} row takes no mode"
    if mode == NO_VALUE:
        return f"{kind} row needs a mode"
    return None if _MODE.fullmatch(mode) else f"bad mode: {mode!r}"


def _source_problem(kind: str, source: str) -> str | None:
    if source == NO_VALUE:
        return f"{kind} row needs a source" if kind in SOURCE_REQUIRED_KINDS else None
    if kind in SOURCELESS_KINDS:
        return f"{kind} row takes no source"
    if source.startswith("/") or PARENT_COMPONENT in source.split("/"):
        return f"bad source: {source!r}"
    return None


def _unusable(number: int, reason: str) -> MounterError:
    return MounterError(UNUSABLE, detail=f"line {number}: {reason}")
