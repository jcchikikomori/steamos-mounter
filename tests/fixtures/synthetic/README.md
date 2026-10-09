# Synthetic Fixtures

This directory holds hand-made command outputs and files for cases the Steam Deck captures in `../deck/` do not
cover (for example `findmnt` read-backs of a mounted `fuseblk` or `ntfs3` volume).

## The First-Line Rule

Every file here, except this README, starts with one header line:

```text
# synthetic: <why>
```

- `<why>` says what the file stands in for and where its content came from (an upstream source file, a real capture
  it was derived from, an observation on the Deck).
- The fixture loader strips this first line before handing the content to a test, so JSON and text synthetics still
  parse.
- `tests/contract/test_fixtures.py` fails when a file here lacks the header.

## Replacing a Synthetic

When a real capture becomes available (on-device items V-11 and V-13), add it to `../deck/` with a row in
`../deck/_capture-index.tsv` and delete the synthetic file it replaces.
