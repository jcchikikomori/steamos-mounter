"""install.sh, uninstall.sh and the entry point on a non-SteamOS host - skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "install.sh
(Contract and Steps)", "uninstall.sh", "Entry Point bin/steamos-mounter",
DD-30, "Installer Contract for the Future Dotfiles Wrapper", "Unit, Contract,
Integration and Property Tests" 3.9). Generated 2026-10-08 by the
acceptance-test-generator. Budget used: 2/3 integration for the feature
"SteamOS-only guard" (FR-17, SM-13).

Test boundary: these tests run the real POSIX scripts and the real entry point
as child processes inside the Docker test image (Debian: /etc/os-release has
ID=debian), as the non-root container user. subprocess is allowed in tests/**
(pyproject per-file-ignores). Nothing is mocked; the pass criterion is that the
platform guard fires before the root guard and before any write.

Gated on the scripts existing (Phase 4 adds them).
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO / "install.sh"
UNINSTALL_SH = REPO / "uninstall.sh"
ENTRY_POINT = REPO / "bin" / "steamos-mounter"
UNSUPPORTED = "unsupported platform: SteamOS only"
EXIT_UNSUPPORTED_PLATFORM = 4


# AC-051: "Given a host that is not SteamOS, then the installer and the services
#   exit with an 'unsupported platform' message and change nothing."
# AC-066 ordering (DD-30): platform guard before the root guard, so a non-root
#   Debian run says "unsupported platform" (exit 4), not "needs root" (exit 3).
# Installer contract: plain lines, prefix "steamos-mounter install:" or
#   "steamos-mounter uninstall:", the actionable line last.
# ROI: 41 (BV:7 x Freq:5 + Legal:0 + Defect:6)
# Behavior: sh <script> on Debian -> exit 4, one prefixed line, no file created
# @category: integration
# @dependency: install.sh, uninstall.sh (real sh)
# @complexity: low
# @real-dependency: /bin/sh, /etc/os-release of the Docker image, tmp_path cwd
@pytest.mark.skipif(not INSTALL_SH.exists(), reason="scripts land in Phase 4")
@pytest.mark.parametrize(
    ("script", "prefix"),
    [
        (INSTALL_SH, "steamos-mounter install:"),
        (UNINSTALL_SH, "steamos-mounter uninstall:"),
    ],
    ids=["install.sh", "uninstall.sh"],
)
def test_scripts_exit_4_on_debian_and_create_nothing(
    script: Path,
    prefix: str,
    tmp_path: Path,
) -> None:
    """Both shell scripts refuse a non-SteamOS host before touching anything.

    Given
      - the Docker test image (ID=debian in /etc/os-release), a non-root uid,
        an empty tmp_path used as cwd, env {"PATH": "/usr/bin:/bin"}
    When
      - subprocess.run(["sh", str(script)], cwd=tmp_path, capture_output=True,
        env=..., timeout=10)
      - and once more with "--no-start" for install.sh (flags do not bypass
        the guard)
    Then (pass criteria)
      - returncode == EXIT_UNSUPPORTED_PLATFORM (4), not 3 (root guard never
        reached, AC-066 ordering) and not 5
      - stdout + stderr is exactly one line, starts with prefix and contains
        UNSUPPORTED; no ESC byte and no byte below 0x20 other than "\\n"
        (NFR-26, tests/contract/test_output.py has the general rule)
      - tmp_path is still empty; /opt/steamos-mounter does not exist; nothing
        under /etc changed (compare a listing of /etc/systemd/system and
        /etc/udev/rules.d before and after; both are unwritable here anyway)
      - shellcheck -s sh passes on the script (run in the same test or as a
        separate contract check; the Docker image ships shellcheck)
    """
    pytest.skip("skeleton: implement in Phase 4 (scripts)")


# SM-13: "on a non-SteamOS host (the Docker test environment), the installer and
#   the service entry point exit with 'unsupported platform' and change 0 files."
# Design Doc "Entry Point": the non-root path reaches cli.main, whose platform
#   guard runs before anything else; --help keeps working in a checkout.
# ROI: 41 (BV:7 x Freq:5 + Legal:0 + Defect:6)
# Behavior: python3 -I bin/steamos-mounter <command> on Debian -> exit 4 with the
#   generic stderr line; --help -> exit 0 and usage text
# @category: integration
# @dependency: bin/steamos-mounter, cli (real python3 -I child process)
# @complexity: low
# @real-dependency: /usr/bin/python3 -I, /etc/os-release of the Docker image
@pytest.mark.skipif(not ENTRY_POINT.exists(), reason="entry point lands in Phase 1")
@pytest.mark.parametrize(
    "command",
    ["list", "scan", "doctor", "internal reconcile --trigger start auto /sys/x"],
)
def test_entry_point_exits_4_on_debian_for_every_command(
    command: str,
    tmp_path: Path,
) -> None:
    """The entry point's platform guard fires for user commands and verbs.

    Given
      - the Docker test image, non-root, the repository checkout (bin/ falls
        back to src/ for a development checkout, never as root)
    When
      - subprocess.run(["/usr/bin/python3", "-I", str(ENTRY_POINT),
        *command.split()], cwd=tmp_path, capture_output=True, timeout=20)
      - and subprocess.run([... ENTRY_POINT, "--help"], ...)
    Then (pass criteria)
      - every command exits 4 with one stderr line
        "steamos-mounter: unsupported platform: SteamOS only." (wording per
        the entry point; the internal verb exits 4 before its root and
        INVOCATION_ID checks, D011/DD-30); stdout is empty
      - "--help" exits 0, prints usage on stdout, and lists no "internal" verb
        and no --key option (AC-012, DD-03)
      - tmp_path stays empty; no __pycache__ is written under REPO/src by the
        child (python3 -I with PYTHONDONTWRITEBYTECODE=1 from the image)
    """
    pytest.skip("skeleton: implement in Phase 4 (CLI skeleton + unit_entry)")
