"""loginctl argv contract: one ``-p`` per property, never a comma list.

Design Doc "Key Dialog Unit" (session check steps 1 to 3) and IP-14. On the
Deck (SteamOS 3.9.2, systemd 261) ``loginctl show-session 3 -p Name,Seat,...``
exits 0 and prints nothing, while ``-p Name -p Seat ...`` prints every
property (fixture ``loginctl-session-3-properties.txt``). Only loginctl is
affected: ``systemctl show -p A,B`` still works, so this guard is scoped to
the modules that run loginctl.

Every module under ``src/`` that names ``tools.loginctl`` is scanned for the
two ways a comma list gets built: a ``",".join(...)`` call and a string
constant shaped like a property list (``Name,Seat``, ``-pName,Seat``,
``--property=Name,Seat``). The scan helpers are exercised on hand-written
sources too, so a scanner that silently finds nothing cannot pass.
"""

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PACKAGE = REPO / "src" / "steamos_mounter"

LOGINCTL_ATTRIBUTE = "loginctl"
COMMA = ","
# A comma list of logind property names, bare or glued to its option.
PROPERTY_LIST = re.compile(r"(?:-p|--property=)?[A-Z][A-Za-z]*(?:,[A-Z][A-Za-z]*)+")
# The modules that run loginctl today; a new one is scanned as well, and this
# set guards against a scan that silently finds none.
EXPECTED_LOGINCTL_MODULES = {"session.py"}

OLD_JOINED_FORM = """
def run(self, verb, name, props):
    argv = (self.ctx.platform.tools.loginctl, verb, name, "-p", ",".join(props))
"""
OLD_LITERAL_FORM = """
argv = (tools.loginctl, "show-session", "3", "-p", "Name,Seat,Active")
"""
GLUED_LITERAL_FORM = """
argv = [tools.loginctl, "show-session", "3", "--property=Name,Seat"]
"""
REPEATED_FLAGS_FORM = """
def run(self, verb, name, props):
    flags = tuple(flag for prop in props for flag in ("-p", prop))
    argv = (self.ctx.platform.tools.loginctl, verb, name, *flags)
    log.info("%s did not match", ", ".join(props))
"""


def runs_loginctl(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.Attribute) and node.attr == LOGINCTL_ATTRIBUTE
        for node in ast.walk(tree)
    )


def is_comma_join(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and isinstance(node.func.value, ast.Constant)
        and node.func.value.value == COMMA
    )


def is_property_list(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and PROPERTY_LIST.fullmatch(node.value) is not None
    )


def comma_lists(source: str) -> list[str]:
    """Each comma-list builder in ``source`` when it runs loginctl, else none."""
    tree = ast.parse(source)
    if not runs_loginctl(tree):
        return []
    return [
        ast.unparse(node)
        for node in ast.walk(tree)
        if is_comma_join(node) or is_property_list(node)
    ]


def loginctl_modules() -> dict[str, str]:
    """Source of every package module that names ``tools.loginctl``."""
    sources = {
        path.relative_to(PACKAGE).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(PACKAGE.rglob("*.py"))
    }
    return {
        name: source
        for name, source in sources.items()
        if runs_loginctl(ast.parse(source))
    }


def test_scan_finds_the_modules_that_run_loginctl():
    assert set(loginctl_modules()) >= EXPECTED_LOGINCTL_MODULES


def test_no_loginctl_module_builds_a_comma_property_list():
    offenders = {
        name: found
        for name, source in loginctl_modules().items()
        if (found := comma_lists(source))
    }

    assert offenders == {}


def test_scan_flags_the_joined_comma_form():
    assert comma_lists(OLD_JOINED_FORM) == ["','.join(props)"]


def test_scan_flags_a_literal_comma_list():
    assert comma_lists(OLD_LITERAL_FORM) == ["'Name,Seat,Active'"]


def test_scan_flags_a_comma_list_glued_to_its_option():
    assert comma_lists(GLUED_LITERAL_FORM) == ["'--property=Name,Seat'"]


def test_scan_passes_repeated_flags_and_a_log_join():
    assert comma_lists(REPEATED_FLAGS_FORM) == []


def test_scan_ignores_modules_that_do_not_run_loginctl():
    # systemctl show takes "-p A,B" fine; only loginctl is guarded.
    source = 'argv = (tools.systemctl, "show", "-p", ",".join(props))\n'

    assert comma_lists(source) == []
