"""The polkit rule: mount the tool's own BitLocker mappings without a password.

Owner decision 2026-10-11 (Stage B, after task 57e): a Dolphin unmount of a
tool-unlocked PERSONAL, then a click to remount, asked for the admin password.
The cleartext mapping was opened by root (``cryptsetup open``), has no drive
object, and udisks only skips auth for a cleartext device it unlocked for the
same uid, so the check becomes ``filesystem-mount-other-seat`` (auth_admin).

``data/49-steamos-mounter.rules`` grants ``polkit.Result.YES`` for exactly
``org.freedesktop.udisks2.filesystem-mount`` and
``org.freedesktop.udisks2.filesystem-mount-other-seat``, and only when the
subject is in ``wheel``, local and active, and the ``device`` detail names one
of the tool's mappings: ``/dev/mapper/<name>``, or ``/dev/dm-N`` whose sysfs
``dm/name`` (read with ``polkit.spawn(["/usr/bin/cat", ...])``) is ``<name>``,
where ``<name>`` is exactly what ``bitlocker.mapping_name`` produces. Anything
else returns nothing, so the default policy decides.

The Docker image has no JavaScript engine, so these tests read the rule as
text: its two regular expression literals are compiled with Python ``re``
(``^``/``$`` stripped and matched with ``fullmatch``, which is JavaScript's
non-multiline meaning: no newline before the end is accepted) and checked
against real and near-miss names; the rest is pinned line by line. The rule
must stay ES5, the subset polkit's Duktape engine runs.
"""

import re
from pathlib import Path

import pytest

from steamos_mounter import bitlocker, config

REPO = Path(__file__).resolve().parents[2]
RULE_FILE = REPO / "data" / "49-steamos-mounter.rules"

MOUNT = "org.freedesktop.udisks2.filesystem-mount"
MOUNT_OTHER_SEAT = "org.freedesktop.udisks2.filesystem-mount-other-seat"
HEADER = (
    "// Installed by steamos-mounter. Do not edit: "
    "install and update overwrite this file."
)
YES_GUARD = "if (name !== null && OWN_MAPPING.test(name)) {"
YES = "return polkit.Result.YES;"
SUBJECT_GUARD = (
    'if (!subject.isInGroup("wheel") || !subject.local || !subject.active) {'
)
ACTION_GUARD = "if (MOUNT_ACTIONS.indexOf(action.id) < 0) {"
DEVICE_LOOKUP = 'var device = action.lookup("device");'
DEVICE_GUARD = 'if (typeof device !== "string") {'
NAME_LOOKUP = "var name = mappingName(device);"
SPAWN = 'return polkit.spawn(["/usr/bin/cat", path]).replace(/\\n$/, "");'
SYSFS_PATH = 'var path = "/sys/class/block/" + dm[1] + "/dm/name";'
DM_EXEC = "var dm = DM_DEVICE.exec(device);"
ADD_RULE = "polkit.addRule(function (action, subject) {"
BARE_RETURN = "return;"
DM_DEVICE_SOURCE = r"^\/dev\/(dm-[0-9]+)$"
# One UUID of each registry form: FAT/exFAT, NTFS, RFC 4122 (the container).
UUIDS = ("1A2B-3C4D", "01D95F1575592A30", "658207d5-5177-4a52-a297-31643c64724d")
OWN_UUID = UUIDS[2]
ES2015 = re.compile(r"\b(?:let|const|class)\b|=>|`")
STRING = re.compile(r'"[^"]*"')
RETURN = re.compile(r"\breturn\b[^;]*;")
ACTION_ID = re.compile(r"org\.freedesktop\.[\w.-]+")


def rule_text() -> str:
    return RULE_FILE.read_text(encoding="utf-8")


def rule_lines() -> list[str]:
    return [line.strip() for line in rule_text().splitlines()]


def code_lines() -> list[str]:
    """The non-empty lines that are not ``//`` comments."""
    return [line for line in rule_lines() if line and not line.startswith("//")]


def regex_literal(name: str) -> str:
    """The source of ``var <name> = /.../;``, delimiters excluded."""
    [found] = re.findall(rf"^\s*var {name} = /(.+)/;$", rule_text(), re.MULTILINE)
    return found


def has_top_level_alternation(source: str) -> bool:
    """Whether ``source`` has a ``|`` outside every group and character class."""
    depth = 0
    in_class = False
    escaped = False
    for char in source:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            return True
    return False


def js_regex(source: str) -> re.Pattern[str]:
    """An anchored JavaScript literal as a Python pattern for ``fullmatch``.

    A top-level ``|`` is refused: in ``^a|b$`` each anchor binds to one
    alternative only, which ``fullmatch`` would hide.
    """
    if not (source.startswith("^") and source.endswith("$")):
        raise ValueError(f"not anchored at both ends: {source!r}")
    if has_top_level_alternation(source):
        raise ValueError(f"top-level alternation: {source!r}")
    return re.compile(source[1:-1])


def own_mapping() -> re.Pattern[str]:
    return js_regex(regex_literal("OWN_MAPPING"))


def dm_device() -> re.Pattern[str]:
    return js_regex(regex_literal("DM_DEVICE"))


def add_rule_body() -> list[str]:
    """The lines of the ``polkit.addRule`` callback, opening line excluded."""
    lines = rule_lines()
    return lines[lines.index(ADD_RULE) + 1 :]


def mapping_name_body() -> list[str]:
    """The lines of the ``mappingName`` helper, up to the ``addRule`` call."""
    lines = rule_lines()
    return lines[lines.index("function mappingName(device) {") : lines.index(ADD_RULE)]


def es2015_syntax(code: str) -> list[str]:
    """ES2015-only tokens in ``code``, ignoring double-quoted strings."""
    return ES2015.findall(STRING.sub('""', code))


# --- the helpers themselves -----------------------------------------------------------


def test_js_regex_refuses_an_unanchored_literal():
    with pytest.raises(ValueError, match="not anchored"):
        js_regex("steamos-mounter-.*")


@pytest.mark.parametrize("source", ["^a|b$", "^(a)|(b)$", "^[|]|b$", "^\\(a|b\\)$"])
def test_js_regex_refuses_a_top_level_alternation(source):
    with pytest.raises(ValueError, match="top-level alternation"):
        js_regex(source)


@pytest.mark.parametrize(
    ("source", "name"),
    [("^(?:a|b)$", "b"), ("^[|]$", "|"), ("^\\|$", "|"), ("^(a(b|c))$", "ac")],
)
def test_js_regex_accepts_alternation_inside_a_group_or_class(source, name):
    assert js_regex(source).fullmatch(name)


def test_js_regex_end_anchor_refuses_a_trailing_newline_like_javascript():
    assert js_regex("^a$").fullmatch("a\n") is None


def test_es2015_syntax_is_found_outside_strings_only():
    code = 'let a = "/sys/class/x"; const f = () => `y`; class B {}'

    assert es2015_syntax(code) == ["let", "const", "=>", "`", "`", "class"]


# --- file shape -----------------------------------------------------------------------


def test_rule_starts_with_the_installed_by_header():
    assert rule_text().splitlines()[0] == HEADER


def test_rule_is_es5_for_polkits_duktape_engine():
    assert es2015_syntax("\n".join(code_lines())) == []


def test_rule_code_has_no_single_quoted_strings():
    """Every string is double-quoted, so the string scans here see them all."""
    assert [line for line in code_lines() if "'" in line] == []


def test_rule_wraps_its_names_in_a_function_scope():
    """polkit loads every rules file into one context: no global names."""
    code = code_lines()

    assert code[0] == "(function () {"
    assert code[-1] == "}());"


def test_rule_ends_with_a_newline():
    assert rule_text().endswith("}());\n")


# --- scope: two actions, wheel, local, active -----------------------------------------


def test_rule_names_exactly_the_two_mount_actions():
    assert ACTION_ID.findall(rule_text()) == [MOUNT, MOUNT_OTHER_SEAT]


def test_rule_returns_early_for_any_other_action():
    body = add_rule_body()

    assert body[:2] == [ACTION_GUARD, BARE_RETURN]


def test_rule_requires_wheel_local_and_active():
    body = add_rule_body()
    guard = body.index(SUBJECT_GUARD)

    assert body[guard + 1] == BARE_RETURN
    assert rule_text().count("isInGroup(") == 1


def test_rule_reads_the_device_detail_and_refuses_a_non_string():
    body = add_rule_body()
    lookup = body.index(DEVICE_LOOKUP)

    assert body[lookup + 1 : lookup + 5] == [
        DEVICE_GUARD,
        BARE_RETURN,
        "}",
        NAME_LOOKUP,
    ]


def test_yes_is_returned_once_and_only_for_an_own_mapping():
    lines = rule_lines()

    assert re.findall(r"polkit\.Result\.\w+", rule_text()) == ["polkit.Result.YES"]
    assert lines[lines.index(YES) - 1] == YES_GUARD


def test_guards_come_before_the_device_and_the_grant():
    body = add_rule_body()
    order = [ACTION_GUARD, SUBJECT_GUARD, DEVICE_LOOKUP, YES_GUARD, YES]

    assert [body.index(line) for line in order] == sorted(
        body.index(line) for line in order
    )


def test_every_other_return_of_the_callback_returns_nothing():
    returns = RETURN.findall("\n".join(add_rule_body()))

    assert returns == [BARE_RETURN, BARE_RETURN, BARE_RETURN, YES]


def test_rule_has_no_other_way_to_say_yes():
    """polkit also takes the string ``"yes"`` and ``polkit.Result["YES"]``."""
    text = rule_text()

    assert re.findall(r"""["']yes["']""", text, re.IGNORECASE) == []
    assert "Result[" not in text


def test_rule_uses_only_addrule_spawn_log_and_yes_from_polkit():
    used = set(re.findall(r"\bpolkit\.[A-Za-z.]+[A-Za-z]", rule_text()))

    assert used == {"polkit.addRule", "polkit.spawn", "polkit.log", "polkit.Result.YES"}


# --- the mapping-name pattern ---------------------------------------------------------


def test_own_mapping_pattern_is_the_prefix_and_the_registry_uuid_forms():
    forms = "|".join(form.pattern for form in config.UUID_FORMS)

    assert re.fullmatch(r"[a-z-]+", bitlocker.MAPPING_PREFIX)  # no regex syntax
    assert regex_literal("OWN_MAPPING") == (f"^{bitlocker.MAPPING_PREFIX}(?:{forms})$")


@pytest.mark.parametrize("uuid", UUIDS)
def test_own_mapping_pattern_accepts_every_mapping_name_form(uuid):
    assert own_mapping().fullmatch(bitlocker.mapping_name(uuid))


@pytest.mark.parametrize(
    "name",
    [
        "steamos-mounter-",
        "steamos-mounter",
        f"STEAMOS-MOUNTER-{OWN_UUID}",
        f"x-steamos-mounter-{OWN_UUID}",
        f"steamos-mounter-{OWN_UUID}x",
        f"steamos-mounter-{OWN_UUID}\n",
        f"steamos-mounter-{OWN_UUID}/../sda1",
        "steamos-mounter-658207d5",
        "steamos-mounter-01D95F1575592A3",
        "steamos-mounter-1A2B3C4D",
        "steamos-mounter-1A2B-3C4G",
        f"bitlk-{OWN_UUID}",
        f"luks-{OWN_UUID}",
        "PAT4T4SHUAWEI_PERSONAL_4_3_2024",
        "vg0-home",
        "",
    ],
    ids=[
        "bare-prefix",
        "prefix-without-dash",
        "wrong-case-prefix",
        "prefix-not-at-start",
        "trailing-character",
        "trailing-newline",
        "path-after-name",
        "short-guid",
        "short-ntfs-serial",
        "fat-without-dash",
        "non-hex",
        "udisks-bitlk",
        "udisks-luks",
        "dolphin-label-name",
        "lvm",
        "empty",
    ],
)
def test_own_mapping_pattern_refuses_other_names(name):
    assert own_mapping().fullmatch(name) is None


# --- the device detail: /dev/mapper/<name> or a validated /dev/dm-N -------------------


def test_mapper_device_is_reduced_to_its_name_by_a_fixed_prefix():
    body = mapping_name_body()

    assert 'var MAPPER_PREFIX = "/dev/mapper/";' in rule_lines()
    assert body[1:4] == [
        "if (device.indexOf(MAPPER_PREFIX) === 0) {",
        "return device.substring(MAPPER_PREFIX.length);",
        "}",
    ]


def test_dm_device_pattern_is_pinned():
    assert regex_literal("DM_DEVICE") == DM_DEVICE_SOURCE


@pytest.mark.parametrize("device", ["/dev/dm-0", "/dev/dm-12"])
def test_dm_device_pattern_accepts_a_dm_node(device):
    assert dm_device().fullmatch(device)


@pytest.mark.parametrize(
    "device",
    [
        "/dev/dm-",
        "/dev/dm-0x",
        "/dev/dm-0/../sda1",
        "/dev/dm-0\n",
        "/dev/dm-a",
        "/dev/sda1",
        "/dev/mapper/dm-0",
        "dm-0",
        "/dev//dm-0",
    ],
)
def test_dm_device_pattern_refuses_anything_else(device):
    assert dm_device().fullmatch(device) is None


def test_dm_device_pattern_captures_only_the_kernel_name():
    assert dm_device().fullmatch("/dev/dm-7").group(1) == "dm-7"


def test_sysfs_path_is_built_only_from_a_validated_dm_name():
    body = mapping_name_body()
    match = body.index(DM_EXEC)

    assert body[match + 1 : match + 5] == [
        "if (dm === null) {",
        "return null;",
        "}",
        SYSFS_PATH,
    ]


def test_spawn_is_one_cat_of_the_sysfs_path_inside_try_catch():
    body = mapping_name_body()
    spawn = body.index(SPAWN)

    assert rule_text().count("polkit.spawn(") == 1
    assert body[spawn - 1] == "try {"
    assert body[spawn + 1] == "} catch (error) {"
    assert body.index(SYSFS_PATH) < spawn


def test_a_failed_read_is_logged_and_falls_through():
    body = mapping_name_body()
    catch = body.index("} catch (error) {")

    assert body[catch + 1 : catch + 3] == [
        'polkit.log("steamos-mounter: cannot read " + path + ": " + error);',
        "return null;",
    ]
