"""Fixture integrity contract.

Design Doc: docs/design/steamos-mounter-design.md (section "Fixtures", under Test
Strategy). The Deck captures under tests/fixtures/deck/ are the single source of
real command output (the Deck cannot recapture them), so this module keeps the
set honest:

- every ``fixture`` row of ``_capture-index.tsv`` exists under ``deck/`` and every
  ``evidence`` row under ``deck/evidence/``;
- the capture hostname never appears anywhere under ``tests/``;
- every synthetic fixture declares itself with a ``# synthetic:`` first line;
- the ``rc`` column, which the fake runner replays, is 1 only for the two
  "not mounted" findmnt captures and ``efi-partsets-all.txt``.

The checks are driven by the index, so adding a capture means adding a row.
"""

import csv
import hashlib
import re
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
FIXTURES = TESTS / "fixtures"
DECK = FIXTURES / "deck"
EVIDENCE = DECK / "evidence"
SYNTHETIC = FIXTURES / "synthetic"
INDEX = DECK / "_capture-index.tsv"

FIXTURE_NOTE = "fixture"
EVIDENCE_NOTE = "evidence"
EXPECTED_FIXTURE_ROWS = 56
EXPECTED_EVIDENCE_ROWS = 5
NONZERO_RC_CAPTURES = {
    "findmnt-sdb5-not-mounted.json": 1,
    "findmnt-dm-0-not-mounted.json": 1,
    "efi-partsets-all.txt": 1,
}
SYNTHETIC_HEADER = b"# synthetic:"
SYNTHETIC_README = "README.md"

# SHA-256 of the real capture hostname, so the name itself is never committed.
# Every hostname-shaped token under tests/ is hashed and compared against it.
CAPTURE_HOSTNAME_SHA256 = (
    "866e2747bcb054d61fbeb9b161d555d845f661f5020a528d569f50f586beaaf4"
)
HOSTNAME_TOKEN = re.compile(rb"[A-Za-z0-9-]+")


def read_index() -> list[dict[str, str]]:
    with INDEX.open(newline="", encoding="utf-8") as index_file:
        return list(csv.DictReader(index_file, delimiter="\t"))


def names_with_note(note: str) -> list[str]:
    return [row["file"] for row in read_index() if row["streams_note"] == note]


def files_under(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())


def test_index_has_expected_columns():
    with INDEX.open(newline="", encoding="utf-8") as index_file:
        header = next(csv.reader(index_file, delimiter="\t"))

    assert header == ["file", "rc", "streams_note"]


def test_index_lists_56_fixtures_and_5_evidence_captures():
    notes = [row["streams_note"] for row in read_index()]

    assert notes.count(FIXTURE_NOTE) == EXPECTED_FIXTURE_ROWS
    assert notes.count(EVIDENCE_NOTE) == EXPECTED_EVIDENCE_ROWS
    assert set(notes) == {FIXTURE_NOTE, EVIDENCE_NOTE}


@pytest.mark.parametrize("name", names_with_note(FIXTURE_NOTE))
def test_fixture_row_exists_under_deck(name):
    assert (DECK / name).is_file(), f"index row {name!r} missing from {DECK}"


@pytest.mark.parametrize("name", names_with_note(EVIDENCE_NOTE))
def test_evidence_row_exists_under_deck_evidence(name):
    assert (EVIDENCE / name).is_file(), f"index row {name!r} missing from {EVIDENCE}"


def test_rc_is_one_only_for_not_mounted_and_partsets_captures():
    nonzero = {row["file"]: int(row["rc"]) for row in read_index() if row["rc"] != "0"}

    assert nonzero == NONZERO_RC_CAPTURES


def test_rc_column_is_numeric_on_every_row():
    bad_rows = [row["file"] for row in read_index() if row["rc"] not in {"0", "1"}]

    assert bad_rows == []


def contains_capture_hostname(data: bytes) -> bool:
    return any(
        hashlib.sha256(token).hexdigest() == CAPTURE_HOSTNAME_SHA256
        for token in HOSTNAME_TOKEN.findall(data)
    )


def test_capture_hostname_appears_nowhere_under_tests():
    offenders = [
        str(path.relative_to(TESTS))
        for path in files_under(TESTS)
        if contains_capture_hostname(path.read_bytes())
    ]

    assert offenders == []


def test_hostname_scan_flags_a_token_with_the_digest(monkeypatch):
    # Negative control: point the digest at a known token and prove the scan fires.
    monkeypatch.setattr(
        "tests.contract.test_fixtures.CAPTURE_HOSTNAME_SHA256",
        hashlib.sha256(b"steamdeck").hexdigest(),
    )

    assert contains_capture_hostname(b"Oct 08 steamdeck kernel: ntfs3")
    assert not contains_capture_hostname(b"Oct 08 otherhost kernel: ntfs3")


def test_journal_capture_uses_the_neutral_hostname():
    lines = (DECK / "journal-kernel-ntfs3.txt").read_text(encoding="utf-8").splitlines()

    assert len(lines) == 14
    assert all(line.split(" ")[1] == "steamdeck" for line in lines)


def test_synthetic_readme_states_the_header_rule():
    readme = (SYNTHETIC / SYNTHETIC_README).read_text(encoding="utf-8")

    assert "# synthetic: <why>" in readme


def test_every_synthetic_fixture_starts_with_the_synthetic_header():
    unlabeled = [
        path.name
        for path in files_under(SYNTHETIC)
        if path.name != SYNTHETIC_README
        and not path.read_bytes().startswith(SYNTHETIC_HEADER)
    ]

    assert unlabeled == []
