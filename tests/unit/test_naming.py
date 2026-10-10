"""Auto-mount names, registry names, unique auto paths and fixed-path rules.

Design Doc "Names and Paths" (the six ``sanitize_label`` steps, the examples
table, "Registry Names", "Fixed-path Rules"), DD-08 (ASCII registry names,
``-2`` to ``-99`` suffixes) and DD-09 (the extended deny-list). PRD AC-004,
AC-027 to AC-029 and AC-054.

Labels are hostile input. The real BitLocker label is taken from the Deck's
lsblk capture and the udev capture of the same partition, so the tests pin the
exact bytes the tool will see. Filesystem facts for the fixed-path rules come
from ``FakePathFacts``: the rules ask "what is at this path", never the real
disk.
"""

import posixpath
import unicodedata
from collections.abc import Iterable

import pytest

from steamos_mounter import naming
from steamos_mounter.blockdev import parse_lsblk_json
from steamos_mounter.errors import ExitCode, InvalidKernelName, RefusedError
from steamos_mounter.naming import (
    AUTO_NAME_MAX_BYTES,
    REGISTRY_NAME_RE,
    NoFreeNameError,
    PathKind,
    fallback_name,
    propose_registry_name,
    sanitize_label,
    unique_auto_path,
    validate_fixed_path,
)
from tests.helpers.fixtures import load_fixture

BASE = "/run/media/deck"
PERSONAL_LABEL = "PAT4T4SHUAWEI PERSONAL 4/3/2024"
PERSONAL_AUTO = "PAT4T4SHUAWEI PERSONAL 4_3_2024"
PERSONAL_REGISTRY = "PAT4T4SHUAWEI_PERSONAL_4_3_2024"
NTFS_FALLBACK = "ntfs-01D95F1575592A30"
# The Dolphin synthetic's label: the same "/" hazard as the real one.
OBAMA_LABEL = "OBAMA BACKUP 1/2/2025"


def udev_property(capture: str, key: str) -> str:
    text = load_fixture(capture).decode("utf-8")
    for line in text.splitlines():
        name, _, value = line.partition("=")
        if name == key:
            return value
    raise KeyError(key)


def real_lsblk_label(kname: str) -> str | None:
    tree = parse_lsblk_json(load_fixture("lsblk-columns-tree.json"))
    return tree.devices[kname].label


# --- registry name proposal (AC-004) -------------------------------------------------


def test_personal_label_proposal():
    label = real_lsblk_label("sdb1")

    proposal = propose_registry_name(label, fallback=NTFS_FALLBACK)

    assert label == PERSONAL_LABEL
    assert proposal == PERSONAL_REGISTRY
    assert posixpath.dirname(posixpath.join(BASE, proposal)) == BASE


def test_personal_label_proposal_from_udev_form():
    # udev replaces blanks with "_" but keeps the "/" in ID_FS_LABEL.
    label = udev_property("udev-sdb1.txt", "ID_FS_LABEL")

    proposal = propose_registry_name(label, fallback=NTFS_FALLBACK)

    assert label == "PAT4T4SHUAWEI_PERSONAL_4/3/2024"
    assert proposal == PERSONAL_REGISTRY


def test_personal_label_encoded_udev_form_is_literal_text():
    # ID_FS_LABEL_ENC is escaped text; read as a label it stays literal.
    label = udev_property("udev-sdb1.txt", "ID_FS_LABEL_ENC")

    assert propose_registry_name(label, fallback=NTFS_FALLBACK) == (
        "PAT4T4SHUAWEI_x20PERSONAL_x204_x2f3_x2f2024"
    )
    assert sanitize_label(label) == "PAT4T4SHUAWEI_x20PERSONAL_x204_x2f3_x2f2024"


def test_personal_auto_name():
    assert sanitize_label(real_lsblk_label("sdb1")) == PERSONAL_AUTO


def test_dolphin_synthetic_label():
    assert sanitize_label(OBAMA_LABEL) == "OBAMA BACKUP 1_2_2025"
    assert propose_registry_name(OBAMA_LABEL, fallback="x") == "OBAMA_BACKUP_1_2_2025"


# --- the examples table ----------------------------------------------------------

# (label, auto name, registry proposal); "" auto name means "use the fallback".
EXAMPLES = (
    (PERSONAL_LABEL, PERSONAL_AUTO, PERSONAL_REGISTRY),
    ("GAMES", "GAMES", "GAMES"),
    ("MÉDIA", "MÉDIA", "MEDIA"),
    (r"M\xc3\x89DIA", "M_xc3_x89DIA", "M_xc3_x89DIA"),
    ("..", "", NTFS_FALLBACK),
    (None, "", NTFS_FALLBACK),
    ("", "", NTFS_FALLBACK),
)


@pytest.mark.parametrize(("label", "auto", "registry"), EXAMPLES)
def test_examples_table(label: str | None, auto: str, registry: str):
    assert sanitize_label(label) == auto
    assert propose_registry_name(label, fallback=NTFS_FALLBACK) == registry


def test_dot_dot_label_falls_back_to_fstype_and_uuid():
    name = sanitize_label("..") or fallback_name("ntfs", "01D95F1575592A30", "sda1")

    assert name == NTFS_FALLBACK


def test_invalid_utf8_label_is_sanitized_without_raising():
    # lsblk bytes are decoded with surrogateescape (DD-01): \xc9 alone is not UTF-8.
    label = b"M\xc9DIA".decode("utf-8", "surrogateescape")

    assert sanitize_label(label) == "M_DIA"
    assert propose_registry_name(label, fallback=NTFS_FALLBACK) == "M_DIA"


def test_decomposed_label_is_composed_first():
    decomposed = "ME\u0301DIA"

    assert sanitize_label(decomposed) == "MÉDIA"
    assert unicodedata.is_normalized("NFC", sanitize_label(decomposed))


# --- sanitize_label steps --------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("a/b\\c<d>e&f;g|h*i?j\"k'l$m`n", "a_b_c_d_e_f_g_h_i_j_k_l_m_n"),
        ("nul\x00here", "nul_here"),
        ("tab\there", "tab_here"),
        ("del\x7fhere", "del_here"),
        ("rlo\u202ehere", "rlo_here"),  # Cf: right-to-left override
        ("pua\ue000here", "pua_here"),  # Co: private use
        ("unassigned\u0378here", "unassigned_here"),  # Cn
        ("lone\udcc3here", "lone_here"),  # Cs: an undecodable byte
    ],
)
def test_step3_replaces_unsafe_characters(label: str, expected: str):
    assert sanitize_label(label) == expected


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("  a   b  ", "a b"),
        ("a\u00a0\u2003b", "a b"),
        ("a___b", "a_b"),
        ("a/ /b", "a_ _b"),
        ("-._ x _.-", "x"),
        (".hidden", "hidden"),
        ("--rf", "rf"),
        ("a//b", "a_b"),
    ],
)
def test_step4_collapses_and_strips(label: str, expected: str):
    assert sanitize_label(label) == expected


def test_step5_truncates_to_128_bytes():
    name = sanitize_label("é" * 200)  # two bytes each

    assert name == "é" * 64
    assert len(name.encode("utf-8")) == AUTO_NAME_MAX_BYTES


def test_step5_truncates_at_a_character_boundary():
    name = sanitize_label("a" + "é" * 64)  # 129 bytes

    assert name == "a" + "é" * 63
    assert len(name.encode("utf-8")) == 127


def test_step5_strips_again_after_truncating():
    name = sanitize_label("a" * 127 + " b")  # the cut leaves a trailing blank

    assert name == "a" * 127


def test_step6_turns_dot_names_into_empty():
    # Step 4 already strips dots, so step 6 is checked on its own as the last guard.
    assert naming._refuse_dot_names(".") == ""
    assert naming._refuse_dot_names("..") == ""
    assert naming._refuse_dot_names("...") == "..."


def test_long_hostile_label():
    name = sanitize_label("../" * 400)

    assert name == ""


# --- registry names --------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("My Drive (2)", "My_Drive_2_"),
        ("..hidden", "hidden"),
        ("_-.x", "x"),
        ("a" * 80, "a" * 64),
        ("Ünïcödé", "Unicode"),
        ("ﬁle", "file"),  # NFKD splits the ligature
        ("日本", NTFS_FALLBACK),
        ("///", NTFS_FALLBACK),
    ],
)
def test_registry_name_rules(label: str, expected: str):
    proposal = propose_registry_name(label, fallback=NTFS_FALLBACK)

    assert proposal == expected
    assert REGISTRY_NAME_RE.fullmatch(proposal)


def test_registry_regex_is_the_design_docs():
    assert REGISTRY_NAME_RE.pattern == r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"


# --- fallback names (AC-029) -----------------------------------------------------


@pytest.mark.parametrize(
    ("fstype", "uuid", "kname", "expected"),
    [
        ("vfat", "C40C-B21F", "sdc1", "vfat-C40C-B21F"),
        ("ntfs", "01D95F1575592A30", "sda1", NTFS_FALLBACK),
        ("exfat", None, "sdc1", "exfat-sdc1"),
        ("exfat", "", "sdc1", "exfat-sdc1"),
        (None, None, "mmcblk0p1", "mmcblk0p1"),
        ("vfat", "../x", "sdc1", "vfat-.._x"),
    ],
)
def test_fallback_name(fstype: str | None, uuid: str | None, kname: str, expected: str):
    assert fallback_name(fstype, uuid, kname) == expected


def test_fallback_name_refuses_invalid_kname():
    with pytest.raises(InvalidKernelName):
        fallback_name("vfat", None, "../sda")


def test_empty_label_fallback_unique():
    # Two unlabelled sticks formatted with the same vfat volume ID.
    first_name = sanitize_label(None) or fallback_name("vfat", "C40C-B21F", "sdc1")
    second_name = sanitize_label("") or fallback_name("vfat", "C40C-B21F", "sdd1")
    mounted: set[str] = set()

    first = unique_auto_path(BASE, first_name, mounted.__contains__)
    mounted.add(first)
    second = unique_auto_path(BASE, second_name, mounted.__contains__)

    assert first_name == "vfat-C40C-B21F"
    assert first == f"{BASE}/vfat-C40C-B21F"
    assert second == f"{BASE}/vfat-C40C-B21F-2"


# --- unique auto paths (AC-028) --------------------------------------------------


def test_collision_suffix():
    taken = {f"{BASE}/GAMES", f"{BASE}/GAMES-2"}

    assert unique_auto_path(BASE, "GAMES", set().__contains__) == f"{BASE}/GAMES"
    assert unique_auto_path(BASE, "GAMES", {f"{BASE}/GAMES"}.__contains__) == (
        f"{BASE}/GAMES-2"
    )
    assert unique_auto_path(BASE, "GAMES", taken.__contains__) == f"{BASE}/GAMES-3"


def test_collision_suffix_stops_at_99():
    taken = {f"{BASE}/GAMES"} | {f"{BASE}/GAMES-{n}" for n in range(2, 99)}

    assert unique_auto_path(BASE, "GAMES", taken.__contains__) == f"{BASE}/GAMES-99"


def test_no_free_name_after_99():
    taken = {f"{BASE}/GAMES"} | {f"{BASE}/GAMES-{n}" for n in range(2, 100)}

    with pytest.raises(NoFreeNameError) as raised:
        unique_auto_path(BASE, "GAMES", taken.__contains__)

    assert raised.value.reason == "no_free_name"
    assert raised.value.exit_code == ExitCode.FAILED


def test_registered_path_never_shadowed():
    # MEDIABOX is registered at the auto path a stick labelled MEDIABOX would get,
    # and the first suffix is a current mount: neither may be reused.
    registered = (f"{BASE}/MEDIABOX",)
    mount_table = {f"{BASE}/MEDIABOX-2"}
    asked: list[str] = []

    def taken(candidate: str) -> bool:
        asked.append(candidate)
        inside_registered = any(
            candidate == path or candidate.startswith(path + "/") for path in registered
        )
        return inside_registered or candidate in mount_table

    path = unique_auto_path(BASE, sanitize_label("MEDIABOX"), taken)

    assert path == f"{BASE}/MEDIABOX-3"
    assert asked == [f"{BASE}/MEDIABOX", f"{BASE}/MEDIABOX-2", f"{BASE}/MEDIABOX-3"]


@pytest.mark.parametrize("name", ["", "a/b", ".", "..", " GAMES", "x\x00", "-x"])
def test_unique_auto_path_refuses_unsanitized_name(name: str):
    with pytest.raises(ValueError, match="not a sanitized name"):
        unique_auto_path(BASE, name, set().__contains__)


# --- fixed-path rules (AC-054, DD-09) --------------------------------------------


class FakePathFacts:
    """``PathFacts`` from a table; every path not listed is missing.

    Ownership is injected here, since the tests do not run as root: every
    directory counts as trusted (root-owned, no group or other write bit)
    unless it is listed in ``untrusted``.
    """

    def __init__(
        self,
        entries: dict[str, PathKind] | None = None,
        *,
        untrusted: Iterable[str] = (),
    ) -> None:
        self.entries = {
            "/": PathKind.NON_EMPTY_DIR,
            "/run": PathKind.NON_EMPTY_DIR,
            "/run/media": PathKind.NON_EMPTY_DIR,
            BASE: PathKind.NON_EMPTY_DIR,
            **(entries or {}),
        }
        self.untrusted = frozenset(untrusted)
        self.asked: list[str] = []

    def kind(self, path: str) -> PathKind:
        self.asked.append(path)
        return self.entries.get(path, PathKind.MISSING)

    def trusted_dir(self, path: str) -> bool:
        self.asked.append(path)
        return path not in self.untrusted


def validate(
    path: str,
    *,
    other_paths: Iterable[str] = (),
    fs: FakePathFacts | None = None,
    mount_base: str = BASE,
) -> None:
    validate_fixed_path(
        path, mount_base=mount_base, other_paths=other_paths, fs=fs or FakePathFacts()
    )


@pytest.mark.parametrize(
    "path",
    [
        f"{BASE}/GAMES",
        f"{BASE}/{PERSONAL_AUTO}",
        f"{BASE}/my.drive_2+x-y",
        f"{BASE}/" + "a" * (255 - len(BASE) - 1),  # exactly 255 bytes
        f"{BASE}/-x",
        f"{BASE}/...",
    ],
)
def test_fixed_path_accepted(path: str):
    assert validate(path) is None


ABSOLUTE = "path must be absolute"
CONTROL = "path contains a control character"
TRAILING = "path must not end with /"
DOTS = "path must not contain . or .. components"
NOT_NORMALIZED = "path is not normalized"
CHARACTERS = "path has a component with characters that are not allowed"
TOO_LONG = "path is longer than 255 bytes"
PROTECTED = "path is a protected directory"
SYSTEM = "path is at or under a system directory"
RUN = "path is under /run but not under /run/media"
BASE_OR_PARENT = "path is the mount base or one of its parents"
NOT_BASE_CHILD = "path must be directly under the mount base"
SYSTEM_DIRECTORIES = (
    "/usr", "/etc", "/var", "/opt", "/boot", "/efi", "/esp", "/proc", "/sys", "/dev",
    "/tmp", "/root", "/srv", "/nix", "/bin", "/sbin", "/lib", "/lib64",
)  # fmt: skip

# (case id, path, expected reason) for the lexical rules 1 to 4.
LEXICAL_REFUSALS = [
    ("rule1-relative", "run/media/deck/X", ABSOLUTE),
    ("rule1-empty", "", ABSOLUTE),
    ("rule1-newline", f"{BASE}/X\n", CONTROL),
    ("rule1-nul", f"{BASE}/X\x00", CONTROL),
    ("rule1-del", f"{BASE}/X\x7f", CONTROL),
    ("rule1-trailing-slash", f"{BASE}/X/", TRAILING),
    ("rule1-dot", f"{BASE}/./X", DOTS),
    ("rule1-dot-dot", f"{BASE}/../deck/X", DOTS),
    ("rule1-escape", f"{BASE}/../../../etc", DOTS),
    ("rule1-double-slash", "/run/media//deck/X", NOT_NORMALIZED),
    ("rule1-leading-double-slash", "//run/media/deck/X", NOT_NORMALIZED),
    ("rule1-non-ascii", f"{BASE}/MÉDIA", CHARACTERS),
    ("rule1-colon", f"{BASE}/a:b", CHARACTERS),
    ("rule1-leading-blank", f"{BASE}/ X", CHARACTERS),
    ("rule1-rlo", f"{BASE}/a\u202eb", CHARACTERS),
    ("rule1-256-bytes", f"{BASE}/" + "a" * (256 - len(BASE) - 1), TOO_LONG),
    ("rule2-root", "/", PROTECTED),
    ("rule2-home", "/home", PROTECTED),
    ("rule2-home-deck", "/home/deck", PROTECTED),
    *((f"rule3-at{path}", path, SYSTEM) for path in SYSTEM_DIRECTORIES),
    *((f"rule3-under{path}", f"{path}/x", SYSTEM) for path in SYSTEM_DIRECTORIES),
    ("rule4-run", "/run", RUN),
    ("rule4-run-user", "/run/user/1000/X", RUN),
    ("rule4-run-mediax", "/run/mediax", RUN),
    ("rule4-run-media", "/run/media", BASE_OR_PARENT),
    ("rule4-mount-base", BASE, BASE_OR_PARENT),
    # Rules 2 to 4 run before rule 9 and keep their reasons (DD-34).
    ("rule3-var-run-spelling", "/var/run/media/deck/X", SYSTEM),
    ("rule9-mnt", "/mnt/X", NOT_BASE_CHILD),
    ("rule9-home-deck-drives", "/home/deck/Drives/X", NOT_BASE_CHILD),
    ("rule9-home-deck-child", "/home/deck/my.drive_2+x-y", NOT_BASE_CHILD),
    ("rule9-under-a-mounted-stick", f"{BASE}/STICK/sub/X", NOT_BASE_CHILD),
    ("rule9-grandchild", f"{BASE}/GAMES/sub", NOT_BASE_CHILD),
    ("rule9-sibling-of-the-base", "/run/media/other", NOT_BASE_CHILD),
    ("rule9-sibling-of-usr", "/usrx", NOT_BASE_CHILD),
    ("rule9-sibling-of-run", "/runner", NOT_BASE_CHILD),
    ("rule9-child-of-root", "/X", NOT_BASE_CHILD),
]
GAMES = f"{BASE}/GAMES"
OVERLAP = "path overlaps another registered path or mount"
PARENT_MISSING = "parent directory does not exist"
# (case id, path, other paths, disk entries, expected reason) for rules 5 to 7.
DISK_AND_REGISTRY_REFUSALS = [
    ("rule5-non-empty-dir", GAMES, (), {GAMES: PathKind.NON_EMPTY_DIR},
     "path is a directory that is not empty"),
    ("rule5-not-a-dir", GAMES, (), {GAMES: PathKind.OTHER},
     "path exists and is not a directory"),
    ("rule6-equal", GAMES, (f"{BASE}/OTHER", GAMES), {}, OVERLAP),
    # A registered path cannot nest in another since rule 9; a current mount can.
    ("rule6-inside", GAMES, (BASE,), {}, OVERLAP),
    ("rule6-containing", GAMES, (f"{GAMES}/sub",), {}, OVERLAP),
    ("rule7-parent-missing", GAMES, (), {BASE: PathKind.MISSING}, PARENT_MISSING),
    ("rule7-parent-not-a-dir", GAMES, (), {BASE: PathKind.OTHER}, PARENT_MISSING),
]  # fmt: skip
FIXED_PATH_REFUSALS = [
    *((case, path, (), {}, reason) for case, path, reason in LEXICAL_REFUSALS),
    *DISK_AND_REGISTRY_REFUSALS,
]


@pytest.mark.parametrize(
    ("path", "other_paths", "entries", "reason"),
    [pytest.param(*row[1:], id=row[0]) for row in FIXED_PATH_REFUSALS],
)
def test_fixed_path_rules(
    path: str,
    other_paths: tuple[str, ...],
    entries: dict[str, PathKind],
    reason: str,
):
    with pytest.raises(RefusedError) as raised:
        validate(path, other_paths=other_paths, fs=FakePathFacts(entries))

    assert raised.value.user_message == reason
    assert raised.value.exit_code == ExitCode.REFUSED


@pytest.mark.parametrize(
    "path", [pytest.param(path, id=case) for case, path, _ in LEXICAL_REFUSALS]
)
def test_lexically_refused_path_is_never_looked_at_on_disk(path: str):
    fs = FakePathFacts()

    with pytest.raises(RefusedError):
        validate(path, fs=fs)

    assert fs.asked == []


@pytest.mark.parametrize(
    ("mount_base", "path", "reason"),
    [
        ("/mnt/drives/deck", "/mnt", BASE_OR_PARENT),
        ("/mnt/drives/deck", "/mnt/drives", BASE_OR_PARENT),
        ("/mnt/drives/deck", "/mnt/drives/deck", BASE_OR_PARENT),
        ("/mnt/drives/deck", "/run/media", BASE_OR_PARENT),
    ],
)
def test_fixed_path_mount_base_follows_the_platform(
    mount_base: str, path: str, reason: str
):
    with pytest.raises(RefusedError, match=reason):
        validate(path, mount_base=mount_base)


def test_fixed_path_deck_base_is_not_special_on_another_platform():
    """Rule 4 follows the platform: the Deck base is refused by rule 9 there."""
    fs = FakePathFacts({BASE: PathKind.EMPTY_DIR})

    with pytest.raises(RefusedError) as raised:
        validate(BASE, mount_base="/mnt/drives/deck", fs=fs)

    assert raised.value.user_message == NOT_BASE_CHILD


def test_fixed_path_rule9_follows_the_platform():
    other_base = "/mnt/drives/deck"
    fs = FakePathFacts({other_base: PathKind.EMPTY_DIR})

    assert validate(f"{other_base}/GAMES", mount_base=other_base, fs=fs) is None
    with pytest.raises(RefusedError, match=NOT_BASE_CHILD):
        validate(f"{BASE}/GAMES", mount_base=other_base, fs=fs)


def test_fixed_path_rule5_empty_directory_is_accepted():
    fs = FakePathFacts({f"{BASE}/GAMES": PathKind.EMPTY_DIR})

    assert validate(f"{BASE}/GAMES", fs=fs) is None


def test_fixed_path_rule6_prefix_sibling_is_not_an_overlap():
    assert validate(f"{BASE}/GAMES2", other_paths=[f"{BASE}/GAMES"]) is None


def test_fixed_path_rule6_accepts_a_one_shot_iterable():
    others = (path for path in [f"{BASE}/A", f"{BASE}/GAMES"])

    with pytest.raises(RefusedError, match="overlaps"):
        validate(f"{BASE}/GAMES", other_paths=others)


def test_fixed_path_rule7_empty_parent_is_accepted():
    fs = FakePathFacts({BASE: PathKind.EMPTY_DIR})

    assert validate(f"{BASE}/GAMES", fs=fs) is None


def test_fixed_path_equal_to_a_current_auto_mount_is_refused():
    """Auto mounts and registered paths share ``<base>/<NAME>``: rule 6 keeps
    ``add`` off a name an unregistered stick is mounted at right now."""
    auto_mount = unique_auto_path(BASE, sanitize_label("GAMES"), set().__contains__)

    with pytest.raises(RefusedError) as raised:
        validate(f"{BASE}/GAMES", other_paths=[auto_mount])

    assert raised.value.user_message == OVERLAP


# --- rule 8: trusted parent directories (owner decision 2026-10-10, option A) ----

UNTRUSTED_PARENT = "a parent directory is a symlink or writable by a non-root user"


@pytest.mark.parametrize(
    "untrusted",
    [
        pytest.param(BASE, id="untrusted-mount-base"),
        pytest.param("/run/media", id="untrusted-grandparent"),
        pytest.param("/run", id="untrusted-run"),
        pytest.param("/", id="untrusted-root"),
    ],
)
def test_fixed_path_rule8_refuses_an_untrusted_parent(untrusted: str):
    path = f"{BASE}/GAMES"
    fs = FakePathFacts(untrusted=[untrusted])

    with pytest.raises(RefusedError) as raised:
        validate(path, fs=fs)

    assert raised.value.user_message == UNTRUSTED_PARENT
    assert raised.value.exit_code == ExitCode.REFUSED
    assert raised.value.detail == (f"fixed path {path!r} refused: {UNTRUSTED_PARENT}")


def test_fixed_path_rule8_checks_every_parent_from_the_root():
    fs = FakePathFacts()

    validate(f"{BASE}/GAMES", fs=fs)

    assert [path for path in fs.asked if path != f"{BASE}/GAMES"] == [
        BASE,  # rule 7
        "/",
        "/run",
        "/run/media",
        BASE,
    ]


def test_fixed_path_rule9_wins_over_rule8_under_a_deck_owned_home():
    """``/home/deck`` is deck-owned, but rule 9 refuses before any disk look."""
    fs = FakePathFacts(
        {"/home/deck/Drives": PathKind.EMPTY_DIR}, untrusted=["/home/deck"]
    )

    with pytest.raises(RefusedError) as raised:
        validate("/home/deck/Drives/GAMES", fs=fs)

    assert raised.value.user_message == NOT_BASE_CHILD
    assert raised.value.detail == (
        f"fixed path '/home/deck/Drives/GAMES' refused: {NOT_BASE_CHILD}"
    )
    assert fs.asked == []


def test_rule9_reason_is_public():
    assert naming.NOT_BASE_CHILD == NOT_BASE_CHILD


def test_fixed_path_rule8_never_asks_about_the_leaf():
    """An existing leaf is rule 5's business: it may be owned by anyone."""
    leaf = f"{BASE}/GAMES"
    fs = FakePathFacts({leaf: PathKind.EMPTY_DIR}, untrusted=[leaf])

    assert validate(leaf, fs=fs) is None


def test_fixed_path_rule7_wins_over_rule8_for_a_missing_parent():
    fs = FakePathFacts({BASE: PathKind.MISSING}, untrusted=[BASE])

    with pytest.raises(RefusedError, match=PARENT_MISSING):
        validate(f"{BASE}/GAMES", fs=fs)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/run/media/deck/GAMES", True),
        ("/home/deck/Drives/GAMES", False),
        ("/GAMES", True),
    ],
)
def test_untrusted_parent_check_on_its_own(path: str, expected: bool):
    """``mountdirs`` asks rule 8 alone for an auto name under the mount base."""
    fs = FakePathFacts(untrusted=["/home/deck"])

    assert naming.has_trusted_parents(path, fs) is expected
