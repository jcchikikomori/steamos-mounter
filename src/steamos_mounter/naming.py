"""Auto-mount names, registry names, unique auto paths and fixed-path rules.

Design Doc "Names and Paths", DD-08 and DD-09; PRD AC-004, AC-027 to AC-029
and AC-054. Labels are hostile input: the real BitLocker label holds ``/``,
and an undecodable lsblk byte arrives as a lone surrogate (DD-01). This module
is the only place a label becomes part of a path.

``sanitize_label`` runs the six Design Doc steps, one function each, in
order. Auto names keep printable Unicode; registry names are ASCII so they
are easy to type in a shell. ``unique_auto_path`` asks the caller what is
taken (mount points, non-empty directories, non-directories, registered fixed
paths), so it never touches the disk itself. ``validate_fixed_path`` checks
the lexical rules first and only then asks ``PathFacts`` about the disk, so a
refused path is never looked at.
"""

import posixpath
import re
import unicodedata
from collections.abc import Callable, Iterable
from enum import StrEnum
from typing import ClassVar, Final, Protocol

from steamos_mounter.blockdev import validate_kname
from steamos_mounter.errors import MounterError, RefusedError

REGISTRY_NAME_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
AUTO_NAME_MAX_BYTES: Final = 128
REGISTRY_NAME_MAX: Final = 64
FIXED_PATH_MAX_BYTES: Final = 255
LAST_SUFFIX: Final = 99
NO_FREE_NAME: Final = "no_free_name"

# sanitize_label step 3: replaced besides surrogates and every C* category.
_DENIED_CHARACTERS: Final = frozenset("/\\<>&;|*?\"'$`")
_WHITESPACE_RUN: Final = re.compile(r"\s+")
_UNDERSCORE_RUN: Final = re.compile(r"_+")
_EDGES: Final = re.compile(r"\A[\s._-]+|[\s._-]+\Z")
_REGISTRY_UNSAFE: Final = re.compile(r"[^A-Za-z0-9._-]")
_REGISTRY_LEADING: Final = re.compile(r"\A[._-]+")
_FIXED_COMPONENT_RE: Final = re.compile(r"[A-Za-z0-9._+-][A-Za-z0-9._ +-]*")

_PROTECTED_PATHS: Final = frozenset({"/", "/home", "/home/deck"})
# Rule 3: refused at or under (AC-054 plus DD-09). "/tmp" is a name to refuse
# here, not a temporary file, hence the S108 waiver.
_SYSTEM_DIRECTORIES: Final = (
    "/usr", "/etc", "/var", "/opt", "/boot", "/efi", "/esp", "/proc", "/sys", "/dev",
    "/tmp", "/root", "/srv", "/nix", "/bin", "/sbin", "/lib", "/lib64",  # noqa: S108
)  # fmt: skip
_RUN: Final = "/run"
_RUN_MEDIA: Final = "/run/media"


class NoFreeNameError(MounterError):
    """``<name>`` and ``<name>-2`` to ``<name>-99`` are all taken (DD-08).

    The caller records ``MountFailed`` with ``reason``.
    """

    reason: ClassVar[str] = NO_FREE_NAME


class PathKind(StrEnum):
    MISSING = "missing"
    EMPTY_DIR = "empty_dir"
    NON_EMPTY_DIR = "non_empty_dir"
    OTHER = "other"  # exists and is not a directory


class PathFacts(Protocol):
    """What is on disk at an absolute host path (fixed-path rules 5 and 7)."""

    def kind(self, path: str) -> PathKind: ...


# --- sanitize_label: one function per Design Doc step -------------------------


def _present(label: str | None) -> str:
    """Step 1: ``None`` or empty -> ``""``."""
    return label or ""


def _compose(text: str) -> str:
    """Step 2: Unicode NFC."""
    return unicodedata.normalize("NFC", text)


def _is_unsafe(character: str) -> bool:
    # Category "Cs" covers the lone surrogates of undecodable bytes.
    return character in _DENIED_CHARACTERS or unicodedata.category(
        character
    ).startswith("C")


def _replace_unsafe(text: str) -> str:
    """Step 3: surrogates, ``C*`` characters and the deny set -> ``_``."""
    return "".join("_" if _is_unsafe(character) else character for character in text)


def _strip_edges(text: str) -> str:
    return _EDGES.sub("", text)


def _collapse_and_strip(text: str) -> str:
    """Step 4: one space per whitespace run, one ``_`` per ``_`` run, strip."""
    text = _WHITESPACE_RUN.sub(" ", text)
    text = _UNDERSCORE_RUN.sub("_", text)
    return _strip_edges(text)


def _truncate(text: str) -> str:
    """Step 5: at most 128 UTF-8 bytes at a character boundary, strip again."""
    # After step 3 the text has no surrogates, so it always encodes; "ignore"
    # drops only a character cut in half at the end.
    head = text.encode("utf-8")[:AUTO_NAME_MAX_BYTES]
    return _strip_edges(head.decode("utf-8", "ignore"))


def _refuse_dot_names(text: str) -> str:
    """Step 6: ``.`` or ``..`` -> ``""``."""
    return "" if text in {".", ".."} else text


def sanitize_label(label: str | None) -> str:
    """The auto-mount name for ``label``; ``""`` means "use the fallback"."""
    text = _present(label)
    text = _compose(text)
    text = _replace_unsafe(text)
    text = _collapse_and_strip(text)
    text = _truncate(text)
    return _refuse_dot_names(text)


# --- registry names, fallback names, auto paths --------------------------------


def propose_registry_name(label: str | None, *, fallback: str) -> str:
    """ASCII registry name for ``label`` (DD-08); ``fallback`` when nothing is left.

    NFKD, drop combining marks, ``_`` for every character outside
    ``[A-Za-z0-9._-]``, collapse ``_``, strip leading ``._-``, cut at 64.
    """
    decomposed = unicodedata.normalize("NFKD", label or "")
    unmarked = "".join(char for char in decomposed if not unicodedata.combining(char))
    ascii_name = _UNDERSCORE_RUN.sub("_", _REGISTRY_UNSAFE.sub("_", unmarked))
    name = _REGISTRY_LEADING.sub("", ascii_name)[:REGISTRY_NAME_MAX]
    return name or fallback


def fallback_name(fstype: str | None, uuid: str | None, kname: str) -> str:
    """``<fstype>-<uuid>``, or ``<fstype>-<kname>`` without a UUID (AC-029).

    The result goes through ``sanitize_label``, since a UUID is read from the
    volume like a label; the validated kname keeps it non-empty.
    """
    validate_kname(kname)
    identity = uuid or kname
    return sanitize_label(f"{fstype}-{identity}" if fstype else identity) or kname


def _candidates(name: str) -> Iterable[str]:
    yield name
    for suffix in range(2, LAST_SUFFIX + 1):
        yield f"{name}-{suffix}"


def unique_auto_path(base: str, name: str, taken: Callable[[str], bool]) -> str:
    """``<base>/<name>``, else the first free ``<base>/<name>-2`` to ``-99``.

    ``name`` must be a ``sanitize_label`` result (or a fallback name), which
    keeps the path a direct child of ``base``. ``taken`` answers for a full
    path (AC-028). Raises ``NoFreeNameError`` when all 99 are taken.
    """
    if not name or sanitize_label(name) != name:
        raise ValueError(f"{name!r} is not a sanitized name")
    for candidate in _candidates(name):
        path = posixpath.join(base, candidate)
        if not taken(path):
            return path
    raise NoFreeNameError(
        "no free mount path name",
        detail=f"{NO_FREE_NAME}: {posixpath.join(base, name)} and -2 to "
        f"-{LAST_SUFFIX} are taken",
    )


# --- fixed paths (AC-054, DD-09) ------------------------------------------------


def _at_or_under(path: str, directory: str) -> bool:
    return path == directory or path.startswith(directory.rstrip("/") + "/")


def _refuse(reason: str, path: str) -> RefusedError:
    return RefusedError(reason, detail=f"fixed path {path!r} refused: {reason}")


def _components(path: str) -> list[str]:
    return [] if path == "/" else path[1:].split("/")


def _syntax_problem(path: str) -> str | None:
    """Rule 1, in an order where every check can be the one that fires."""
    if not path.startswith("/"):
        return "path must be absolute"
    if any(unicodedata.category(char) == "Cc" for char in path):
        return "path contains a control character"
    if path != "/" and path.endswith("/"):
        return "path must not end with /"
    components = _components(path)
    if "." in components or ".." in components:
        return "path must not contain . or .. components"
    if "//" in path or posixpath.normpath(path) != path:
        return "path is not normalized"
    if not all(_FIXED_COMPONENT_RE.fullmatch(part) for part in components):
        return "path has a component with characters that are not allowed"
    # Every component is ASCII by now, so characters are bytes.
    if len(path) > FIXED_PATH_MAX_BYTES:
        return f"path is longer than {FIXED_PATH_MAX_BYTES} bytes"
    return None


def _location_problem(path: str, mount_base: str) -> str | None:
    """Rules 2 to 4: protected, system, ``/run`` and the mount base's line."""
    if path in _PROTECTED_PATHS:
        return "path is a protected directory"
    if any(_at_or_under(path, directory) for directory in _SYSTEM_DIRECTORIES):
        return "path is at or under a system directory"
    if _at_or_under(path, _RUN) and not _at_or_under(path, _RUN_MEDIA):
        return "path is under /run but not under /run/media"
    if path == _RUN_MEDIA or _at_or_under(mount_base, path):
        return "path is the mount base or one of its parents"
    return None


def _entry_problem(path: str, fs: PathFacts) -> str | None:
    """Rule 5: an existing non-empty directory or non-directory."""
    kind = fs.kind(path)
    if kind is PathKind.NON_EMPTY_DIR:
        return "path is a directory that is not empty"
    if kind is PathKind.OTHER:
        return "path exists and is not a directory"
    return None


def _overlaps(path: str, other_paths: Iterable[str]) -> bool:
    """Rule 6: equal to, inside, or containing another path."""
    return any(
        _at_or_under(path, other) or _at_or_under(other, path) for other in other_paths
    )


def _parent_missing(path: str, fs: PathFacts) -> bool:
    """Rule 7: the tool creates only the leaf (DD-26)."""
    parent_kind = fs.kind(posixpath.dirname(path))
    return parent_kind not in {PathKind.EMPTY_DIR, PathKind.NON_EMPTY_DIR}


def validate_fixed_path(
    path: str, *, mount_base: str, other_paths: Iterable[str], fs: PathFacts
) -> None:
    """Refuse ``path`` as a fixed mount path unless it passes every rule.

    ``other_paths`` holds the other registered paths and the current
    steamos-mounter mounts. Raises ``RefusedError`` (exit 8) whose message is
    the reason.
    """
    reason = _syntax_problem(path) or _location_problem(path, mount_base)
    if reason is None:
        reason = _entry_problem(path, fs)
    if reason is None and _overlaps(path, other_paths):
        reason = "path overlaps another registered path or mount"
    if reason is None and _parent_missing(path, fs):
        reason = "parent directory does not exist"
    if reason is not None:
        raise _refuse(reason, path)
