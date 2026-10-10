"""Install manifest parser.

Design Doc "Install Manifest (Authoritative)" and the ``manifest.py`` interface
under "Module Responsibilities": ``parse`` splits each line on any run of
spaces or tabs, skips ``#`` comments, requires ``format 1`` as the first
record, and refuses anything it cannot read with a generic ``MounterError``
whose journal detail names the line. ``etc_paths`` is the doctor's expected
set from the manifest: ``file`` and ``registry`` rows under ``/etc/``.
"""

import pytest

from steamos_mounter.errors import MounterError
from steamos_mounter.manifest import Entry, etc_paths, parse

HEADER = "# a comment\nformat\t1\n"
DIR_ROW = "dir\t/etc/steamos-mounter\troot:root\t0755\t-\tregistry-dir\n"
FILE_ROW = (
    "file\t/etc/udev/rules.d/90-steamos-mounter.rules\troot:root\t0644\t"
    "data/90-steamos-mounter.rules\tudev-rule\n"
)
REGISTRY_ROW = (
    "registry\t/etc/steamos-mounter/config.toml\troot:root\t0644\t-\tregistry\n"
)
LINK_ROW = "link\t/opt/steamos-mounter/bin\troot:root\t-\tcurrent/bin\trelease-link\n"
UNUSABLE = "the install manifest is unusable"


def _refused(text: str) -> MounterError:
    with pytest.raises(MounterError) as caught:
        parse(text)
    return caught.value


# --- parse: accepted input -------------------------------------------------------


def test_parse_reads_each_kind_into_an_entry():
    entries = parse(HEADER + DIR_ROW + FILE_ROW + REGISTRY_ROW + LINK_ROW)

    assert entries == (
        Entry("dir", "/etc/steamos-mounter", "root:root", 0o755, "-", "registry-dir"),
        Entry(
            "file",
            "/etc/udev/rules.d/90-steamos-mounter.rules",
            "root:root",
            0o644,
            "data/90-steamos-mounter.rules",
            "udev-rule",
        ),
        Entry(
            "registry",
            "/etc/steamos-mounter/config.toml",
            "root:root",
            0o644,
            "-",
            "registry",
        ),
        Entry(
            "link",
            "/opt/steamos-mounter/bin",
            "root:root",
            None,
            "current/bin",
            "release-link",
        ),
    )


def test_parse_splits_on_any_run_of_spaces_or_tabs():
    text = "format  1\ndir \t /var/lib/steamos-mounter/keys\troot:root   0700 - keys\n"

    assert parse(text) == (
        Entry("dir", "/var/lib/steamos-mounter/keys", "root:root", 0o700, "-", "keys"),
    )


def test_parse_skips_comments_before_and_between_records():
    text = "# head\n# kind path\nformat\t1\n# registry row below\n" + REGISTRY_ROW

    assert [entry.kind for entry in parse(text)] == ["registry"]


def test_parse_of_a_manifest_with_no_records_is_empty():
    assert parse("format\t1\n") == ()


def test_parse_accepts_a_link_without_a_source():
    text = (
        "format\t1\nlink\t/opt/steamos-mounter/current\troot:root\t-\t-\trelease-link\n"
    )

    assert parse(text)[0].source == "-"


def test_parse_accepts_text_without_a_final_newline():
    assert len(parse(HEADER + DIR_ROW.rstrip("\n"))) == 1


# --- parse: refusals ----------------------------------------------------------------


def test_refusal_is_generic_with_the_line_in_the_detail():
    error = _refused(HEADER + "dir\t/etc/x\troot:root\t0755\t-\n")

    assert str(error) == UNUSABLE
    assert error.detail == "line 3: expected 6 fields, found 5"


@pytest.mark.parametrize(
    ("text", "detail"),
    [
        ("", "no format line"),
        ("# only a comment\n", "no format line"),
        ("format\t2\n", "line 1: unsupported format: 'format 2'"),
        ("format\n", "line 1: unsupported format: 'format'"),
        ("format\t1\textra\n", "line 1: unsupported format: 'format 1 extra'"),
        (
            DIR_ROW,
            "line 1: unsupported format: "
            "'dir /etc/steamos-mounter root:root 0755 - registry-dir'",
        ),
    ],
)
def test_format_1_must_be_the_first_record(text, detail):
    assert _refused(text).detail == detail


@pytest.mark.parametrize(
    ("row", "detail"),
    [
        ("dir\t/a\troot:root\t0755\t-\n", "expected 6 fields, found 5"),
        ("dir\t/a\troot:root\t0755\t-\tx\ty\n", "expected 6 fields, found 7"),
        ("socket\t/a\troot:root\t0755\t-\tx\n", "unknown kind: 'socket'"),
        ("format\t1\n", "expected 6 fields, found 2"),
        (
            "dir\tetc/x\troot:root\t0755\t-\tx\n",
            "path is not absolute and normal: 'etc/x'",
        ),
        (
            "dir\t/etc/../x\troot:root\t0755\t-\tx\n",
            "path is not absolute and normal: '/etc/../x'",
        ),
        (
            "dir\t/etc//x\troot:root\t0755\t-\tx\n",
            "path is not absolute and normal: '/etc//x'",
        ),
        (
            "dir\t/etc/x/\troot:root\t0755\t-\tx\n",
            "path is not absolute and normal: '/etc/x/'",
        ),
        ("dir\t/a\troot\t0755\t-\tx\n", "bad owner: 'root'"),
        ("dir\t/a\troot:\t0755\t-\tx\n", "bad owner: 'root:'"),
        ("dir\t/a\troot:root\t755\t-\tx\n", "bad mode: '755'"),
        ("dir\t/a\troot:root\t0789\t-\tx\n", "bad mode: '0789'"),
        ("dir\t/a\troot:root\t-\t-\tx\n", "dir row needs a mode"),
        ("file\t/a\troot:root\t-\tdata/a\tx\n", "file row needs a mode"),
        ("link\t/a\troot:root\t0755\tb\tx\n", "link row takes no mode"),
        ("file\t/a\troot:root\t0644\t-\tx\n", "file row needs a source"),
        ("file\t/a\troot:root\t0644\t/data/a\tx\n", "bad source: '/data/a'"),
        ("file\t/a\troot:root\t0644\tdata/../../a\tx\n", "bad source: 'data/../../a'"),
        ("link\t/a\troot:root\t-\t../b\tx\n", "bad source: '../b'"),
        ("dir\t/a\troot:root\t0755\tdata/a\tx\n", "dir row takes no source"),
        ("registry\t/a\troot:root\t0644\tdata/a\tx\n", "registry row takes no source"),
        ("\n", "blank line"),
        ("  \t\n", "blank line"),
    ],
)
def test_bad_record_is_refused_with_its_line_number(row, detail):
    assert _refused(HEADER + row).detail == f"line 3: {detail}"


def test_duplicate_path_is_refused():
    error = _refused(HEADER + DIR_ROW + DIR_ROW)

    assert error.detail == "line 4: duplicate path: '/etc/steamos-mounter'"


# --- etc_paths -----------------------------------------------------------------------


def test_etc_paths_are_file_and_registry_rows_under_etc_in_order():
    rows = (
        DIR_ROW
        + FILE_ROW
        + "dir\t/var/lib/steamos-mounter\troot:root\t0755\t-\tstate\n"
        + REGISTRY_ROW
        + "file\t/opt/steamos-mounter/x\troot:root\t0644\tdata/x\tx\n"
        + "file\t/etcetera/x\troot:root\t0644\tdata/x\tx\n"
        + LINK_ROW
    )

    assert etc_paths(parse(HEADER + rows)) == (
        "/etc/udev/rules.d/90-steamos-mounter.rules",
        "/etc/steamos-mounter/config.toml",
    )


def test_etc_paths_of_no_entries_is_empty():
    assert etc_paths(()) == ()
