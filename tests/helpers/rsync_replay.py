"""Replay SteamOS's /etc keep-list filter with the real rsync.

Port of the review's verifier script (``verify/rsync_doctor_check.py``), the
evidence that the keep-list drop-in covers every installed /etc path. The
algorithm is unchanged; only the structure is new:

1. Filter: the keep-list with ``^/etc`` removed from each line, then for each
   drop-in a ``"\\n"`` and its lines with ``^/etc`` removed and trailing
   newlines stripped (``holo-sync-var`` ``build_etc_rsync_config``).
2. Scratch tree: ``src/`` holds each expected path without its ``/etc/``
   prefix, an empty 0644 file or a symlink with the given target text; ``dst/``
   is empty.
3. ``rsync --dry-run --out-format='%i %n'`` with ``holo-sync-var``'s flags.
4. Parse: ``<11-character itemize> <name>``; names ending in ``/`` are
   directories and skipped; a second itemize character ``f`` (file) or ``L``
   (symlink) means the path is kept.

Deliberately independent of ``steamos_mounter``: the doctor implementation is
tested against this replay, not against itself.
"""

import re
import subprocess
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path

RSYNC = "/usr/bin/rsync"
RSYNC_TIMEOUT_SECONDS = 30
SCRATCH_PREFIX = "steamos-mounter-doctor-"
ETC_PREFIX = "/etc/"
ETC_AT_LINE_START = re.compile(r"(?m)^/etc")
OCTAL_ESCAPE = re.compile(r"\\#([0-7]{3})")
ITEMIZE_WIDTH = 11
# The itemize string, one space, and a name of at least one character.
MIN_ITEM_LINE = ITEMIZE_WIDTH + 2
KEPT_TYPES = "fL"
FILE_MODE = 0o644


def build_filter(keep_list: str, dropins: Iterable[str]) -> str:
    """The rsync include-from text built from the keep-list and drop-in texts."""
    text = ETC_AT_LINE_START.sub("", keep_list)
    for dropin in dropins:
        text += "\n" + ETC_AT_LINE_START.sub("", dropin).rstrip("\n")
    return text


def decode_name(name: str) -> str:
    """Undo rsync's ``\\#ooo`` escapes, one code point per escape.

    One code point per escape is right for ASCII; ``replay`` refuses
    non-ASCII paths, so it never meets a multi-byte name.
    """
    return OCTAL_ESCAPE.sub(lambda match: chr(int(match[1], 8)), name)


def parse_itemized(stdout: str) -> set[str]:
    """``/etc`` paths that the dry run's itemized output shows as kept."""
    covered: set[str] = set()
    for line in stdout.splitlines():
        if not line.strip():
            continue
        if len(line.split(" ", 1)[0]) != ITEMIZE_WIDTH:
            raise ValueError(f"rsync line without an itemize string: {line!r}")
        if len(line) < MIN_ITEM_LINE:
            continue
        itemize, name = line[:ITEMIZE_WIDTH], line[ITEMIZE_WIDTH + 1 :]
        if name.endswith("/"):
            continue
        if itemize[1] in KEPT_TYPES:
            covered.add(ETC_PREFIX + decode_name(name))
    return covered


def replay(
    keep_list: str,
    dropins: Iterable[str],
    expected: Mapping[str, str | None],
) -> set[str]:
    """The ``/etc`` paths of ``expected`` that the keep-list and drop-ins keep.

    ``expected`` maps each ``/etc/...`` path to a symlink target text, or to
    ``None`` for a regular file. Raises ``ValueError`` for a path outside
    ``/etc/`` or with non-ASCII characters, and ``RuntimeError`` when rsync
    does not exit 0.
    """
    for path in expected:
        if not path.startswith(ETC_PREFIX) or not path.isascii():
            raise ValueError(f"expected path must be ASCII under /etc/: {path!r}")
    filter_text = build_filter(keep_list, dropins)
    with tempfile.TemporaryDirectory(prefix=SCRATCH_PREFIX) as scratch:
        scratch_dir = Path(scratch)
        source, destination = scratch_dir / "src", scratch_dir / "dst"
        destination.mkdir()
        _seed_source(source, expected)
        filter_file = scratch_dir / "filter"
        filter_file.write_text(filter_text, encoding="utf-8")
        result = subprocess.run(
            _rsync_argv(filter_file, source, destination),
            capture_output=True,
            text=True,
            timeout=RSYNC_TIMEOUT_SECONDS,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"rsync exited {result.returncode}: {result.stderr.strip()[:400]}"
        )
    return parse_itemized(result.stdout)


def _seed_source(source: Path, expected: Mapping[str, str | None]) -> None:
    for path, link_target in expected.items():
        entry = source / path.removeprefix(ETC_PREFIX)
        entry.parent.mkdir(parents=True, exist_ok=True)
        if link_target is None:
            entry.touch()
            entry.chmod(FILE_MODE)
        else:
            entry.symlink_to(link_target)


def _rsync_argv(filter_file: Path, source: Path, destination: Path) -> list[str]:
    return [
        RSYNC,
        "-rlpgoDHA",
        "--delete",
        "--one-file-system",
        "--checksum",
        "--prune-empty-dirs",
        "--dry-run",
        "--out-format=%i %n",
        "--include=*/",
        f"--include-from={filter_file}",
        "--exclude=*",
        f"{source}/",
        f"{destination}/",
    ]
