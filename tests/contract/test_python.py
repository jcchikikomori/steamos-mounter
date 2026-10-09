"""Python rules contract.

Design Doc: docs/design/steamos-mounter-design.md (section "Python
Constraints", rules 1 and 3, and the note under "pyproject.toml": the version
lives in two places on purpose, and a test asserts they match).

- Runtime is the stdlib only: every import in every file under ``src/`` is a
  ``sys.stdlib_module_names`` entry or ``steamos_mounter`` itself.
- No module or package basename under ``src/steamos_mounter`` shadows a stdlib
  module.
- ``steamos_mounter.__version__`` equals ``[project] version``.
- The Deck's Python (fixture ``python-runtime.txt``) meets ``requires-python``.

The scan helpers are exercised on hand-written sources too, so a scanner that
silently finds nothing cannot pass.
"""

import ast
import re
import sys
import tomllib
from pathlib import Path

import pytest

import steamos_mounter

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"
PACKAGE = SRC / "steamos_mounter"
PYPROJECT = REPO / "pyproject.toml"
DECK_RUNTIME = REPO / "tests" / "fixtures" / "deck" / "python-runtime.txt"

PACKAGE_NAME = "steamos_mounter"
ALLOWED_TOP_LEVEL = frozenset(sys.stdlib_module_names) | {PACKAGE_NAME}
# Package mechanics, not importable module names that could shadow anything.
DUNDER_MODULES = frozenset({"__init__", "__main__"})
# Present from task P1-T03 on; guards against an empty or misdirected scan.
EXPECTED_MODULES = {"__init__", "__main__", "errors", "output"}


def imported_top_levels(source: str) -> set[str]:
    """Top-level names of every absolute import in ``source``.

    Relative imports (``from . import x``) stay inside the package and are
    skipped.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.partition(".")[0])
    return names


def foreign_imports(source: str) -> set[str]:
    return imported_top_levels(source) - ALLOWED_TOP_LEVEL


def shadowing_names(paths: list[Path]) -> set[str]:
    """Module and package basenames that collide with a stdlib module."""
    names = {path.stem for path in paths} | {path.parent.name for path in paths}
    return (names - DUNDER_MODULES) & frozenset(sys.stdlib_module_names)


def source_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def requires_python_floor() -> tuple[int, int]:
    with PYPROJECT.open("rb") as pyproject:
        spec = tomllib.load(pyproject)["project"]["requires-python"]
    match = re.fullmatch(r">=(\d+)\.(\d+)", spec)
    assert match, f"unexpected requires-python: {spec!r}"
    return int(match[1]), int(match[2])


def test_scan_finds_the_package_modules():
    assert {path.stem for path in source_files()} >= EXPECTED_MODULES


@pytest.mark.parametrize("path", source_files(), ids=lambda path: path.name)
def test_source_imports_only_stdlib_and_the_package(path):
    assert foreign_imports(path.read_text(encoding="utf-8")) == set()


def test_no_module_basename_shadows_the_stdlib():
    assert shadowing_names(source_files()) == set()


def test_import_scan_flags_third_party_imports():
    source = "import requests\nfrom yaml import safe_load\nimport os.path\n"

    assert foreign_imports(source) == {"requests", "yaml"}


def test_import_scan_allows_package_and_relative_imports():
    source = (
        "from steamos_mounter.errors import ExitCode\n"
        "from . import output\n"
        "from .errors import MounterError\n"
        "import json, logging.handlers\n"
    )

    assert foreign_imports(source) == set()


def test_shadow_scan_flags_a_stdlib_named_module():
    paths = [
        PACKAGE / "logging.py",
        PACKAGE / "errors.py",
        PACKAGE / "platforms" / "__init__.py",
    ]

    assert shadowing_names(paths) == {"logging"}


def test_shadow_scan_flags_a_stdlib_named_package():
    assert shadowing_names([PACKAGE / "json" / "__init__.py"]) == {"json"}


def test_version_matches_pyproject():
    with PYPROJECT.open("rb") as pyproject:
        project_version = tomllib.load(pyproject)["project"]["version"]

    assert steamos_mounter.__version__ == project_version


def test_deck_python_meets_requires_python():
    first_line = DECK_RUNTIME.read_text(encoding="utf-8").splitlines()[0]
    match = re.match(r"version (\d+)\.(\d+)\.", first_line)
    assert match, f"unexpected capture line: {first_line!r}"

    assert (int(match[1]), int(match[2])) >= requires_python_floor()
