"""The keep-list drop-in's patterns and rsync's wildcard meaning.

Design Doc "Keep-list Drop-in (Authoritative)" and ADR-0004 D2. Shared by the
drop-in contract test and the installer tree test, which checks that every
path an install adds under ``/etc`` is one the drop-in keeps.
"""

import re
from pathlib import Path

DROPIN_FILE = Path(__file__).resolve().parents[2] / "data" / "steamos-mounter.conf"
COMMENT = "#"
WILDCARD = re.compile(r"(\*\*|\*|\?)")
WILDCARD_REGEX = {"**": ".*", "*": "[^/]*", "?": "[^/]"}


def dropin_patterns(text: str) -> list[str]:
    """Pattern lines: neither blank nor comments (rsync skips ``#`` lines)."""
    return [line for line in text.splitlines() if line and not line.startswith(COMMENT)]


def glob_matches(pattern: str, path: str) -> bool:
    """rsync's wildcard meaning: ``**`` crosses ``/``, ``*`` and ``?`` do not."""
    regex = "".join(
        WILDCARD_REGEX.get(piece, re.escape(piece))
        for piece in WILDCARD.split(pattern)
        if piece
    )
    return re.fullmatch(regex, path) is not None
