"""Load command-output fixtures: Deck captures first, then synthetic stand-ins.

Design Doc "Fixtures": real captures live in ``tests/fixtures/deck/`` and are
returned verbatim. Hand-made files in ``tests/fixtures/synthetic/`` start with a
``# synthetic: <why>`` line, which the loader strips so JSON and text synthetics
parse like the real output they stand in for.
"""

import csv
from pathlib import Path, PurePath

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
DECK = FIXTURES / "deck"
SYNTHETIC = FIXTURES / "synthetic"
INDEX_NAME = "_capture-index.tsv"
SYNTHETIC_HEADER = b"# synthetic:"


def strip_synthetic_header(data: bytes) -> bytes:
    """Drop the first line when it is a ``# synthetic:`` header."""
    if not data.startswith(SYNTHETIC_HEADER):
        return data
    _, _, body = data.partition(b"\n")
    return body


def load_fixture(name: str) -> bytes:
    """Bytes of fixture ``name`` (a path relative to ``deck/`` or ``synthetic/``)."""
    deck_path = DECK / name
    if deck_path.is_file():
        return deck_path.read_bytes()
    synthetic_path = SYNTHETIC / name
    if synthetic_path.is_file():
        return strip_synthetic_header(synthetic_path.read_bytes())
    raise FileNotFoundError(f"fixture {name!r} is in neither {DECK} nor {SYNTHETIC}")


def fixture_rc(name: str) -> int:
    """Exit status the Deck command returned for capture ``name``.

    Looked up by file name in ``_capture-index.tsv``, so ``evidence/<file>``
    and ``<file>`` give the same answer. Synthetic files have no row.
    """
    file_name = PurePath(name).name
    with (DECK / INDEX_NAME).open(newline="", encoding="utf-8") as index_file:
        for row in csv.DictReader(index_file, delimiter="\t"):
            if row["file"] == file_name:
                return int(row["rc"])
    raise KeyError(f"no {INDEX_NAME} row for fixture {name!r}")
