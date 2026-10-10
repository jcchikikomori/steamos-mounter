"""The data files equal the Design Doc's authoritative blocks, byte for byte.

Design Doc "Authoritative Text in This Document": the three unit templates,
the udev rule, the keep-list drop-in and the install manifest must match the
document byte for byte unless the document is revised. For each ``data/``
file this test finds its heading, takes the next fenced block and compares it
with the shipped file. The document shows the manifest with spaces (its
formatter converts tabs), so each manifest record from the document is joined
with single tabs first; comment lines are compared as they are.

``docs/`` is gitignored and local only, so a fresh clone has no Design Doc:
the comparison tests skip there with that reason and run wherever the
document exists. The extraction helper is tested on inline text, so it runs
everywhere and cannot silently find nothing.
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DATA = REPO / "data"
DESIGN_DOC = REPO / "docs" / "design" / "steamos-mounter-design.md"

FENCE = "```"
COMMENT = "#"
TAB = "\t"
MANIFEST = "manifest.tsv"
HEADINGS = {
    "steamos-mounter@.service": "#### `data/steamos-mounter@.service`",
    "steamos-mounter-auto@.service": "#### `data/steamos-mounter-auto@.service`",
    "steamos-mounter-key@.service": "#### `data/steamos-mounter-key@.service`",
    "90-steamos-mounter.rules": "### udev Rule (Authoritative)",
    "steamos-mounter.conf": "### Keep-list Drop-in (Authoritative)",
    MANIFEST: "### Install Manifest (Authoritative)",
}
NO_DESIGN_DOC = (
    "docs/design/steamos-mounter-design.md is absent: docs/ is gitignored, "
    "so a fresh clone cannot compare the data files with it"
)


def authoritative_block(document: str, heading: str) -> str:
    """The first fenced block after ``heading``, with a final newline.

    Raises ``ValueError`` when the heading or a closed fence is missing.
    """
    lines = document.split("\n")
    if heading not in lines:
        raise ValueError(f"heading not found: {heading!r}")
    after = lines[lines.index(heading) + 1 :]
    opening = next(
        (index for index, line in enumerate(after) if line.startswith(FENCE)), None
    )
    if opening is None:
        raise ValueError(f"no fenced block after {heading!r}")
    body = after[opening + 1 :]
    if FENCE not in body:
        raise ValueError(f"unclosed fenced block after {heading!r}")
    return "\n".join(body[: body.index(FENCE)]) + "\n"


def tab_separated(block: str) -> str:
    """Records joined with single tabs; comment lines unchanged."""
    return "\n".join(
        line if line.startswith(COMMENT) else TAB.join(line.split())
        for line in block.split("\n")
    )


def expected_bytes(name: str) -> bytes:
    block = authoritative_block(DESIGN_DOC.read_text(encoding="utf-8"), HEADINGS[name])
    if name == MANIFEST:
        block = tab_separated(block)
    return block.encode("utf-8")


# --- the extraction helpers -------------------------------------------------------


def test_block_is_the_first_fence_after_the_heading():
    document = "# Doc\n### A\n\ntext\n\n```ini\nx=1\n\ny=2\n```\n\n```text\nz\n```\n"

    assert authoritative_block(document, "### A") == "x=1\n\ny=2\n"


@pytest.mark.parametrize(
    ("document", "problem"),
    [
        ("### B\n```\nx\n```\n", "heading not found"),
        ("### A\ntext only\n", "no fenced block"),
        ("### A\n```\nx\n", "unclosed fenced block"),
    ],
)
def test_block_extraction_refuses_what_it_cannot_find(document, problem):
    with pytest.raises(ValueError, match=problem):
        authoritative_block(document, "### A")


def test_manifest_records_get_single_tabs_and_comments_stay():
    block = "# kind path owner\nformat 1\ndir  /a root:root 0755 - x\n"

    assert tab_separated(block) == (
        "# kind path owner\nformat\t1\ndir\t/a\troot:root\t0755\t-\tx\n"
    )


def test_every_data_file_has_an_authoritative_heading():
    assert {path.name for path in DATA.glob("*")} == set(HEADINGS)


# --- data files against the Design Doc --------------------------------------------


@pytest.mark.skipif(not DESIGN_DOC.is_file(), reason=NO_DESIGN_DOC)
@pytest.mark.parametrize("name", sorted(HEADINGS))
def test_data_file_equals_its_authoritative_block(name):
    assert (DATA / name).read_bytes() == expected_bytes(name)
