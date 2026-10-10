"""Keep-list drop-in and install manifest consistency.

Design Doc "Keep-list Drop-in (Authoritative)" (rules from ADR-0004 D2),
"Install Manifest (Authoritative)", "Runtime State Records" (D002) and the
"doctor Keep-list Check (Authoritative)".

The five drop-in rules: every pattern starts with ``/etc/``, has no backslash,
names only steamos-mounter files, the file lists itself, and its patterns map
one to one onto the manifest's ``/etc`` file and registry rows, plus the
``.device.wants`` link pattern. The manifest is ``format 1``, single tabs, no
whitespace inside a field, and its rows are pinned literally below; its
``/run`` rows equal ``records.RUNTIME_DIRS``.

The ``rsync`` tests replay SteamOS's own filter with the real rsync against the
Deck's keep-list captures: the drop-in keeps every manifest ``/etc`` path and a
sample wants link (positive control), the drop-in alone with an empty keep-list
keeps them too (ADR-0004 D2: no reliance on Valve's defaults), and without it the
registry and the udev rule are lost (negative control).
"""

from pathlib import Path

import pytest

from steamos_mounter import records
from steamos_mounter.manifest import Entry, etc_paths, parse
from tests.helpers.dropin import COMMENT, dropin_patterns, glob_matches
from tests.helpers.fixtures import load_fixture
from tests.helpers.rsync_replay import replay

REPO = Path(__file__).resolve().parents[2]
DATA = REPO / "data"
DROPIN_FILE = DATA / "steamos-mounter.conf"
MANIFEST_FILE = DATA / "manifest.tsv"

ETC = "/etc/"
RUN = "/run/"
DROPIN_INSTALLED = "/etc/atomic-update.conf.d/steamos-mounter.conf"
REGISTRY = "/etc/steamos-mounter/config.toml"
UDEV_RULE = "/etc/udev/rules.d/90-steamos-mounter.rules"
UNIT_TEMPLATE = "/etc/systemd/system/steamos-mounter@.service"
WANTS_PATTERN = "/etc/systemd/system/*.device.wants/steamos-mounter@*.service"
MEDIABOX_LINK = (
    "/etc/systemd/system/dev-disk-by\\x2duuid-01D95F1575592A30.device.wants/"
    "steamos-mounter@dev-disk-by\\x2duuid-01D95F1575592A30.service"
)
# The manifest's /etc file and registry rows, in manifest order.
ETC_PATHS = (
    REGISTRY,
    DROPIN_INSTALLED,
    UNIT_TEMPLATE,
    "/etc/systemd/system/steamos-mounter-auto@.service",
    "/etc/systemd/system/steamos-mounter-key@.service",
    UDEV_RULE,
)
# A path component starting with one of these can only match our own files.
OWN_PREFIXES = ("steamos-mounter", "90-steamos-mounter")
DROPIN_COMMENT = "##"
TAB = "\t"

ROOT = "root:root"
MANIFEST_ROWS = (
    Entry("dir", "/etc/steamos-mounter", ROOT, 0o755, "-", "registry-dir"),
    Entry("registry", REGISTRY, ROOT, 0o644, "-", "registry"),
    Entry(
        "file", DROPIN_INSTALLED, ROOT, 0o644, "data/steamos-mounter.conf", "keep-list"
    ),
    Entry("file", UNIT_TEMPLATE, ROOT, 0o644, "data/steamos-mounter@.service", "unit"),
    Entry(
        "file",
        "/etc/systemd/system/steamos-mounter-auto@.service",
        ROOT,
        0o644,
        "data/steamos-mounter-auto@.service",
        "unit",
    ),
    Entry(
        "file",
        "/etc/systemd/system/steamos-mounter-key@.service",
        ROOT,
        0o644,
        "data/steamos-mounter-key@.service",
        "unit",
    ),
    Entry("file", UDEV_RULE, ROOT, 0o644, "data/90-steamos-mounter.rules", "udev-rule"),
    Entry("dir", "/var/lib/steamos-mounter", ROOT, 0o755, "-", "state"),
    Entry("dir", "/var/lib/steamos-mounter/keys", ROOT, 0o700, "-", "keys"),
    Entry("dir", "/run/steamos-mounter", ROOT, 0o755, "-", "runtime"),
    Entry("dir", "/run/steamos-mounter/records", ROOT, 0o755, "-", "runtime"),
    Entry(
        "dir", "/run/steamos-mounter/records/registered", ROOT, 0o755, "-", "runtime"
    ),
    Entry("dir", "/run/steamos-mounter/records/auto", ROOT, 0o755, "-", "runtime"),
    Entry("dir", "/run/steamos-mounter/locks", ROOT, 0o700, "-", "runtime"),
    Entry(
        "link", "/opt/steamos-mounter/bin", ROOT, None, "current/bin", "release-link"
    ),
    Entry("link", "/opt/steamos-mounter/current", ROOT, None, "-", "release-link"),
)


def dropin_text() -> str:
    return DROPIN_FILE.read_text(encoding="utf-8")


def manifest_text() -> str:
    return MANIFEST_FILE.read_text(encoding="utf-8")


def manifest_records(text: str) -> list[str]:
    return [line for line in text.splitlines() if not line.startswith(COMMENT)]


def names_only_own_files(pattern: str) -> bool:
    """True when some component's literal start ties every match to us."""
    return any(component.startswith(OWN_PREFIXES) for component in pattern.split("/"))


def all_conf_dropin() -> str:
    """Valve's example drop-in without the ``### <path>`` line the capture added."""
    text = load_fixture("atomic-update.conf.d-all.conf").decode("utf-8")
    return text.split("\n", 1)[1]


def expected_etc() -> dict[str, str | None]:
    """The doctor's expected set: manifest ``/etc`` rows plus one wants link."""
    expected: dict[str, str | None] = dict.fromkeys(ETC_PATHS)
    expected[MEDIABOX_LINK] = UNIT_TEMPLATE
    return expected


# --- the glob and ownership helpers ---------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("/etc/steamos-mounter/**", "/etc/steamos-mounter/config.toml", True),
        ("/etc/steamos-mounter/**", "/etc/steamos-mounter/a/b", True),
        ("/etc/systemd/system/*.service", "/etc/systemd/system/a/b.service", False),
        (WANTS_PATTERN, MEDIABOX_LINK, True),
        (WANTS_PATTERN, "/etc/systemd/system/x.device.wants/other@x.service", False),
        ("/etc/a?c", "/etc/abc", True),
        ("/etc/a?c", "/etc/a/c", False),
        ("/etc/a.b", "/etc/axb", False),
    ],
)
def test_glob_follows_rsync_wildcards(pattern, path, expected):
    assert glob_matches(pattern, path) is expected


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("/etc/steamos-mounter/**", True),
        (WANTS_PATTERN, True),
        ("/etc/udev/rules.d/90-steamos-mounter.rules", True),
        ("/etc/systemd/system/*.service", False),
        ("/etc/**", False),
        ("/etc/*steamos-mounter*/x", False),
    ],
)
def test_ownership_check_rejects_patterns_that_reach_foreign_files(pattern, expected):
    assert names_only_own_files(pattern) is expected


# --- the five drop-in rules (ADR-0004 D2) ---------------------------------------------


def test_every_dropin_pattern_starts_with_etc():
    patterns = dropin_patterns(dropin_text())

    assert patterns
    assert [pattern for pattern in patterns if not pattern.startswith(ETC)] == []


def test_no_dropin_line_has_a_backslash():
    assert "\\" not in dropin_text()


def test_every_dropin_pattern_names_only_steamos_mounter_files():
    patterns = dropin_patterns(dropin_text())

    assert [pattern for pattern in patterns if not names_only_own_files(pattern)] == []


def test_dropin_lists_itself():
    assert DROPIN_INSTALLED in dropin_patterns(dropin_text())


def test_dropin_patterns_map_one_to_one_onto_the_manifest_etc_rows():
    patterns = dropin_patterns(dropin_text())
    file_patterns = [pattern for pattern in patterns if pattern != WANTS_PATTERN]
    paths = ETC_PATHS

    patterns_per_path = {
        path: [pattern for pattern in file_patterns if glob_matches(pattern, path)]
        for path in paths
    }
    paths_per_pattern = {
        pattern: [path for path in paths if glob_matches(pattern, path)]
        for pattern in file_patterns
    }

    assert WANTS_PATTERN in patterns
    assert {
        path: len(hits) for path, hits in patterns_per_path.items()
    } == dict.fromkeys(paths, 1)
    assert {
        pattern: len(hits) for pattern, hits in paths_per_pattern.items()
    } == dict.fromkeys(file_patterns, 1)


def test_dropin_comments_use_valves_double_hash():
    comments = [line for line in dropin_text().splitlines() if line.startswith(COMMENT)]

    assert comments
    assert [line for line in comments if not line.startswith(DROPIN_COMMENT)] == []


# --- manifest format ------------------------------------------------------------------


def test_manifest_first_record_is_format_1():
    assert manifest_records(manifest_text())[0] == f"format{TAB}1"


def test_manifest_records_use_single_tabs_and_no_whitespace_in_fields():
    bad = [
        line
        for line in manifest_records(manifest_text())
        if line != TAB.join(line.split()) or " " in line
    ]

    assert bad == []


def test_manifest_rows_kinds_and_modes():
    assert parse(manifest_text()) == MANIFEST_ROWS


def test_manifest_etc_paths_are_the_file_and_registry_rows():
    assert etc_paths(parse(manifest_text())) == ETC_PATHS


def test_every_file_row_source_is_shipped_in_data():
    sources = [entry.source for entry in parse(manifest_text()) if entry.kind == "file"]

    assert [source for source in sources if not (REPO / source).is_file()] == []


def test_runtime_dirs_equal_the_manifest_run_rows():
    run_rows = tuple(
        (entry.path, entry.mode)
        for entry in parse(manifest_text())
        if entry.path.startswith(RUN)
    )

    assert run_rows == records.RUNTIME_DIRS


# --- rsync replay of SteamOS's keep-list filter ---------------------------------------


@pytest.mark.rsync
def test_dropin_keeps_every_manifest_etc_path_and_a_wants_link():
    keep_list = load_fixture("atomic-update-keep.conf").decode("utf-8")
    expected = expected_etc()

    covered = replay(keep_list, [all_conf_dropin(), dropin_text()], expected)

    assert set(expected) - covered == set()


@pytest.mark.rsync
def test_dropin_alone_keeps_every_manifest_etc_path_and_a_wants_link():
    """ADR-0004 D2: the setup does not depend on Valve keeping its defaults."""
    expected = expected_etc()

    covered = replay("", [dropin_text()], expected)

    assert set(expected) - covered == set()


@pytest.mark.rsync
def test_without_the_dropin_the_registry_and_the_udev_rule_are_lost():
    keep_list = load_fixture("atomic-update-keep.conf").decode("utf-8")
    expected = expected_etc()

    covered = replay(keep_list, [all_conf_dropin()], expected)

    assert set(expected) - covered == {REGISTRY, UDEV_RULE}
