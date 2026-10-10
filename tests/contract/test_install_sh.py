"""``install.sh`` reads the version the package declares.

Design Doc "install.sh (Contract and Steps)" step 5: the release directory is
``releases/<version>-<UTC stamp>``, with the version read from
``src/steamos_mounter/__init__.py`` by one ``sed`` expression; an empty
result is exit 5. The expression is taken from the script itself and run by
the real ``sh`` and ``sed`` of the Docker image, so a change on either side
(the script or the ``__version__`` line) that breaks the read fails here.
"""

import re
import subprocess
from pathlib import Path

from steamos_mounter import __version__

REPO = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO / "install.sh"
PACKAGE_INIT = REPO / "src" / "steamos_mounter" / "__init__.py"
SH = "/bin/sh"
SED_CALL = re.compile(r"sed -n '([^']+)'")


def version_expression() -> str:
    found = SED_CALL.findall(INSTALL_SH.read_text(encoding="utf-8"))
    assert len(found) == 1, found
    return found[0]


def run_sed(path: Path) -> str:
    result = subprocess.run(
        [SH, "-c", 'sed -n "$1" "$2"', "sh", version_expression(), str(path)],
        capture_output=True,
        timeout=10,
        check=True,
    )
    return result.stdout.decode()


def test_the_sed_expression_yields_the_package_version():
    assert run_sed(PACKAGE_INIT) == f"{__version__}\n"


def test_the_sed_expression_yields_nothing_for_an_unexpected_line(tmp_path):
    init = tmp_path / "__init__.py"
    init.write_text("__version__ = '0.1.0'\n", encoding="utf-8")  # single quotes

    assert run_sed(init) == ""
