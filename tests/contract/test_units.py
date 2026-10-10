"""systemd unit template contract.

Design Doc "systemd Units (Authoritative)" and its directive rationale table
(D001, DD-17); ADR-0001 guidance 2, 3, 6 and 7; ADR-0002 D1; NFR-03.

Every row of the rationale table is asserted present (with its value and
section) or absent. Each directive must sit in a section that systemd 261
accepts, from the small allow-list below; ``systemd-analyze verify`` on the
Deck is the real proof (deferred to the on-device task), this table is the
Docker stand-in until then. The ``data/`` files are also checked for the
``.editorconfig`` rules: UTF-8, LF, a final newline, no trailing whitespace.
"""

from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DATA = REPO / "data"

REGISTERED = "steamos-mounter@.service"
AUTO = "steamos-mounter-auto@.service"
KEY = "steamos-mounter-key@.service"
ALL_UNITS = (REGISTERED, AUTO, KEY)
MOUNT_UNITS = (REGISTERED, AUTO)

UNIT = "Unit"
SERVICE = "Service"
COMMENT_PREFIXES = ("#", ";")
CONTINUATION = "\\"
ENTRY = "/usr/bin/python3 -I /opt/steamos-mounter/bin/steamos-mounter"

# systemd 261 allow-list: the section each directive this project uses belongs
# to (systemd.unit(5), systemd.service(5), systemd.exec(5), systemd.kill(5)).
ALLOWED_SECTION = {
    "Description": UNIT,
    "BindsTo": UNIT,
    "After": UNIT,
    "RequiresMountsFor": UNIT,
    "StartLimitIntervalSec": UNIT,
    "StartLimitBurst": UNIT,
    "CollectMode": UNIT,
    "DefaultDependencies": UNIT,
    "Type": SERVICE,
    "RemainAfterExit": SERVICE,
    "ExitType": SERVICE,
    "KillMode": SERVICE,
    "TimeoutStartSec": SERVICE,
    "TimeoutStopSec": SERVICE,
    "RuntimeMaxSec": SERVICE,
    "UMask": SERVICE,
    "SyslogIdentifier": SERVICE,
    "ExecStart": SERVICE,
    "ExecReload": SERVICE,
    "ExecStop": SERVICE,
    "ExecStopPost": SERVICE,
}
# ADR-0001 guidance 3: no restarts and no private mount namespace.
ABSENT_DIRECTIVES = (
    "Restart",
    "PrivateTmp",
    "ProtectSystem",
    "ProtectHome",
    "PrivateDevices",
    "PrivateMounts",
    "ReadOnlyPaths",
    "BindPaths",
)
POLLING_SUFFIXES = (".timer", ".path", ".socket")

EXEC_LINES = {
    REGISTERED: {
        "ExecStart": f"{ENTRY} internal reconcile --trigger start registered %f",
        "ExecReload": f"{ENTRY} internal reconcile --trigger reload registered %f",
        "ExecStop": f"{ENTRY} internal teardown registered %f",
        "ExecStopPost": f"{ENTRY} internal sweep registered %f",
    },
    AUTO: {
        "ExecStart": f"{ENTRY} internal reconcile --trigger start auto %f",
        "ExecReload": f"{ENTRY} internal reconcile --trigger reload auto %f",
        "ExecStop": f"{ENTRY} internal teardown auto %f",
        "ExecStopPost": f"{ENTRY} internal sweep auto %f",
    },
    KEY: {
        "ExecStart": f"{ENTRY} internal key %f",
        "ExecStopPost": f"{ENTRY} internal key-stop %f",
    },
}


DESCRIPTIONS = {
    REGISTERED: "steamos-mounter registered volume %f",
    AUTO: "steamos-mounter auto-mount for %f",
    KEY: "steamos-mounter key dialog for %f",
}
REQUIRES_MOUNTS = "/opt/steamos-mounter /var/lib/steamos-mounter"
# Every directive of every template, in file order. An extra directive fails,
# even an allow-listed one (RuntimeMaxSec= in a mount unit would stop the unit
# and kill the FUSE child it owns).
FULL_DIRECTIVES = {
    REGISTERED: (
        (UNIT, "Description", "steamos-mounter registered volume %f"),
        (UNIT, "BindsTo", "%i.device"),
        (UNIT, "After", "%i.device"),
        (UNIT, "RequiresMountsFor", REQUIRES_MOUNTS),
        (UNIT, "StartLimitIntervalSec", "60"),
        (UNIT, "StartLimitBurst", "5"),
        (SERVICE, "Type", "oneshot"),
        (SERVICE, "RemainAfterExit", "yes"),
        (SERVICE, "ExitType", "main"),
        (SERVICE, "KillMode", "control-group"),
        (SERVICE, "TimeoutStartSec", "90"),
        (SERVICE, "TimeoutStopSec", "60"),
        (SERVICE, "UMask", "0022"),
        (SERVICE, "SyslogIdentifier", "steamos-mounter"),
        (
            SERVICE,
            "ExecStart",
            f"{ENTRY} internal reconcile --trigger start registered %f",
        ),
        (
            SERVICE,
            "ExecReload",
            f"{ENTRY} internal reconcile --trigger reload registered %f",
        ),
        (SERVICE, "ExecStop", f"{ENTRY} internal teardown registered %f"),
        (SERVICE, "ExecStopPost", f"{ENTRY} internal sweep registered %f"),
    ),
    AUTO: (
        (UNIT, "Description", "steamos-mounter auto-mount for %f"),
        (UNIT, "BindsTo", "%i.device"),
        (UNIT, "After", "%i.device"),
        (UNIT, "RequiresMountsFor", REQUIRES_MOUNTS),
        (UNIT, "StartLimitIntervalSec", "60"),
        (UNIT, "StartLimitBurst", "5"),
        (SERVICE, "Type", "oneshot"),
        (SERVICE, "RemainAfterExit", "yes"),
        (SERVICE, "ExitType", "main"),
        (SERVICE, "KillMode", "control-group"),
        (SERVICE, "TimeoutStartSec", "90"),
        (SERVICE, "TimeoutStopSec", "60"),
        (SERVICE, "UMask", "0022"),
        (SERVICE, "SyslogIdentifier", "steamos-mounter"),
        (SERVICE, "ExecStart", f"{ENTRY} internal reconcile --trigger start auto %f"),
        (SERVICE, "ExecReload", f"{ENTRY} internal reconcile --trigger reload auto %f"),
        (SERVICE, "ExecStop", f"{ENTRY} internal teardown auto %f"),
        (SERVICE, "ExecStopPost", f"{ENTRY} internal sweep auto %f"),
    ),
    KEY: (
        (UNIT, "Description", "steamos-mounter key dialog for %f"),
        (UNIT, "BindsTo", "%i.device"),
        (UNIT, "After", "%i.device"),
        (UNIT, "RequiresMountsFor", REQUIRES_MOUNTS),
        (UNIT, "StartLimitIntervalSec", "60"),
        (UNIT, "StartLimitBurst", "5"),
        (UNIT, "CollectMode", "inactive-or-failed"),
        (SERVICE, "Type", "exec"),
        (SERVICE, "ExitType", "main"),
        (SERVICE, "KillMode", "control-group"),
        (SERVICE, "RuntimeMaxSec", "300"),
        (SERVICE, "TimeoutStopSec", "30"),
        (SERVICE, "UMask", "0077"),
        (SERVICE, "SyslogIdentifier", "steamos-mounter"),
        (SERVICE, "ExecStart", f"{ENTRY} internal key %f"),
        (SERVICE, "ExecStopPost", f"{ENTRY} internal key-stop %f"),
    ),
}


@dataclass(frozen=True, slots=True)
class Directive:
    section: str
    key: str
    value: str


def parse_unit(text: str) -> tuple[Directive, ...]:
    """The ``Key=Value`` lines of a unit file with the section each sits in.

    Raises ``ValueError`` for a directive outside any section, a line that is
    neither a section, a comment nor ``Key=Value``, and a continuation line
    (none of the templates needs one).
    """
    directives: list[Directive] = []
    section = ""
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(COMMENT_PREFIXES):
            continue
        if stripped.endswith(CONTINUATION):
            raise ValueError(f"line {number}: continuation line")
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        key, separator, value = stripped.partition("=")
        if not separator or not key:
            raise ValueError(f"line {number}: not Key=Value: {stripped!r}")
        if not section:
            raise ValueError(f"line {number}: directive before any section")
        directives.append(Directive(section, key.strip(), value.strip()))
    return tuple(directives)


def sections_of(text: str) -> list[str]:
    return [
        line.strip()[1:-1]
        for line in text.splitlines()
        if line.strip().startswith("[") and line.strip().endswith("]")
    ]


def misplaced(directives: tuple[Directive, ...]) -> list[Directive]:
    """Directives outside the allow-list or in a section systemd rejects."""
    return [
        directive
        for directive in directives
        if ALLOWED_SECTION.get(directive.key) != directive.section
    ]


def unit_text(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")


def directives_of(name: str) -> tuple[Directive, ...]:
    return parse_unit(unit_text(name))


def value(name: str, section: str, key: str) -> str | None:
    """The one value of ``key`` in ``section``; ``None`` when absent."""
    values = [
        directive.value
        for directive in directives_of(name)
        if directive.section == section and directive.key == key
    ]
    assert len(values) <= 1, f"{name}: {key}= set {len(values)} times"
    return values[0] if values else None


def keys_of(name: str) -> set[str]:
    return {directive.key for directive in directives_of(name)}


# --- the parser and the allow-list check catch what they must -------------------------


def test_parser_reads_sections_keys_and_values():
    text = "# c\n[Unit]\nDescription=x %f\n\n[Service]\nType = oneshot\n"

    assert parse_unit(text) == (
        Directive(UNIT, "Description", "x %f"),
        Directive(SERVICE, "Type", "oneshot"),
    )


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("Description=x\n", "directive before any section"),
        ("[Unit]\nDescription\n", "not Key=Value"),
        ("[Service]\nExecStart=/bin/true \\\n", "continuation line"),
    ],
)
def test_parser_refuses_what_systemd_would_read_differently(text, problem):
    with pytest.raises(ValueError, match=problem):
        parse_unit(text)


def test_allow_list_flags_collect_mode_in_the_service_section():
    directives = parse_unit("[Service]\nCollectMode=inactive-or-failed\n")

    assert misplaced(directives) == [
        Directive(SERVICE, "CollectMode", "inactive-or-failed")
    ]


def test_allow_list_flags_an_unknown_directive():
    directives = parse_unit("[Unit]\nWantedBy=multi-user.target\n")

    assert misplaced(directives) == [Directive(UNIT, "WantedBy", "multi-user.target")]


# --- every directive sits where systemd 261 accepts it (D001) -------------------------


@pytest.mark.parametrize("name", ALL_UNITS)
def test_every_directive_is_in_a_section_systemd_accepts(name):
    assert misplaced(directives_of(name)) == []


@pytest.mark.parametrize("name", ALL_UNITS)
def test_only_unit_and_service_sections_in_that_order(name):
    assert sections_of(unit_text(name)) == [UNIT, SERVICE]


@pytest.mark.parametrize("name", ALL_UNITS)
def test_no_directive_is_set_twice(name):
    pairs = [(directive.section, directive.key) for directive in directives_of(name)]

    assert len(pairs) == len(set(pairs))


# --- rationale table: present ---------------------------------------------------------


@pytest.mark.parametrize("name", ALL_UNITS)
def test_binds_to_and_is_ordered_after_its_device(name):
    assert value(name, UNIT, "BindsTo") == "%i.device"
    assert value(name, UNIT, "After") == "%i.device"


@pytest.mark.parametrize("name", ALL_UNITS)
def test_requires_mounts_for_opt_and_var(name):
    assert (
        value(name, UNIT, "RequiresMountsFor")
        == "/opt/steamos-mounter /var/lib/steamos-mounter"
    )


@pytest.mark.parametrize("name", ALL_UNITS)
def test_start_limit_is_5_starts_in_60_seconds(name):
    assert value(name, UNIT, "StartLimitIntervalSec") == "60"
    assert value(name, UNIT, "StartLimitBurst") == "5"


@pytest.mark.parametrize("name", MOUNT_UNITS)
def test_mount_units_are_oneshot_and_stay_active(name):
    assert value(name, SERVICE, "Type") == "oneshot"
    assert value(name, SERVICE, "RemainAfterExit") == "yes"


@pytest.mark.parametrize("name", ALL_UNITS)
def test_kill_mode_and_exit_type_are_explicit(name):
    assert value(name, SERVICE, "KillMode") == "control-group"
    assert value(name, SERVICE, "ExitType") == "main"


@pytest.mark.parametrize("name", MOUNT_UNITS)
def test_mount_units_set_a_90_second_start_timeout(name):
    assert value(name, SERVICE, "TimeoutStartSec") == "90"


@pytest.mark.parametrize(
    ("name", "seconds"), [(REGISTERED, "60"), (AUTO, "60"), (KEY, "30")]
)
def test_stop_timeout_is_not_the_platform_default(name, seconds):
    assert value(name, SERVICE, "TimeoutStopSec") == seconds


def test_key_unit_is_exec_with_a_300_second_runtime_cap():
    assert value(KEY, SERVICE, "Type") == "exec"
    assert value(KEY, SERVICE, "RuntimeMaxSec") == "300"
    assert "RemainAfterExit" not in keys_of(KEY)
    assert "TimeoutStartSec" not in keys_of(KEY)


def test_key_unit_collect_mode_is_in_the_unit_section():
    assert value(KEY, UNIT, "CollectMode") == "inactive-or-failed"
    assert value(KEY, SERVICE, "CollectMode") is None


@pytest.mark.parametrize("name", MOUNT_UNITS)
def test_mount_units_keep_failed_instances_visible(name):
    assert "CollectMode" not in keys_of(name)


@pytest.mark.parametrize(
    ("name", "umask"), [(REGISTERED, "0022"), (AUTO, "0022"), (KEY, "0077")]
)
def test_umask_in_the_service_section(name, umask):
    assert value(name, SERVICE, "UMask") == umask


@pytest.mark.parametrize("name", ALL_UNITS)
def test_one_syslog_identifier_for_every_unit(name):
    assert value(name, SERVICE, "SyslogIdentifier") == "steamos-mounter"


# --- rationale table: absent and default kept -----------------------------------------


@pytest.mark.parametrize("name", ALL_UNITS)
def test_no_install_section(name):
    assert "Install" not in sections_of(unit_text(name))


@pytest.mark.parametrize("name", ALL_UNITS)
@pytest.mark.parametrize("key", ABSENT_DIRECTIVES)
def test_no_restart_and_no_private_mount_namespace(name, key):
    assert key not in keys_of(name)


@pytest.mark.parametrize("name", ALL_UNITS)
def test_default_dependencies_are_kept(name):
    assert value(name, UNIT, "DefaultDependencies") in {None, "yes"}


# --- Exec lines ----------------------------------------------------------------------


@pytest.mark.parametrize("name", ALL_UNITS)
def test_exec_lines_are_exact(name):
    execs = {
        directive.key: directive.value
        for directive in directives_of(name)
        if directive.key.startswith("Exec")
    }

    assert execs == EXEC_LINES[name]


@pytest.mark.parametrize("name", ALL_UNITS)
def test_description_names_the_unescaped_instance(name):
    assert value(name, UNIT, "Description") == DESCRIPTIONS[name]


@pytest.mark.parametrize("name", ALL_UNITS)
def test_unit_holds_exactly_the_authoritative_directives(name):
    found = tuple(
        (directive.section, directive.key, directive.value)
        for directive in directives_of(name)
    )

    assert found == FULL_DIRECTIVES[name]


# --- data/ as a whole ----------------------------------------------------------------


def test_data_holds_the_three_templates_and_no_polling_unit():
    names = {path.name for path in DATA.iterdir()}

    assert set(ALL_UNITS) <= names
    assert [name for name in names if name.endswith(POLLING_SUFFIXES)] == []


@pytest.mark.parametrize("path", sorted(DATA.glob("*")), ids=lambda path: path.name)
def test_data_file_is_utf8_lf_with_a_final_newline(path):
    data = path.read_bytes()
    text = data.decode("utf-8")

    assert b"\r" not in data
    assert text.endswith("\n")
    assert not text.endswith("\n\n")
    assert [line for line in text.split("\n") if line != line.rstrip()] == []
