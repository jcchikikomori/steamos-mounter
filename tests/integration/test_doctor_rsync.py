"""doctor keep-list coverage with the real rsync - integration skeleton.

Design Doc: docs/design/steamos-mounter-design.md (sections "doctor Keep-list
Check (Authoritative)", "Keep-list Drop-in (Authoritative)", "Install Manifest
(Authoritative)", "Unit, Contract, Integration and Property Tests" 3.7).
Generated 2026-10-08 by the acceptance-test-generator. Budget used: 2/3
integration for the feature "health check / update survival" (FR-13, FR-11).

Test boundary: rsync is NOT mocked (Design Doc "Mock Boundary Decisions": "doctor
must match rsync's own filter semantics"); it is /usr/bin/rsync from the Docker
image, hence @pytest.mark.rsync. Everything else is real files under
HostPaths(root=tmp_path): the keep-list and Valve's all.conf come from the Deck
captures, the drop-in and manifest from the repository's data/ directory. No
FakeRunner script is needed beyond letting rsync run for real (the runner seam
executes it: use SubprocessRunner for this module, or a FakeRunner that passes
rsync through).

This module ports the verifier's replay approach (rsync_doctor_check.py in the
review scratchpad): build the filter from the fixtures, run the dry run, parse
the itemize column, positive and negative control.

Skipped until steamos_mounter.doctor exists.
"""

from pathlib import Path

import pytest

doctor = pytest.importorskip("steamos_mounter.doctor")
manifest = pytest.importorskip("steamos_mounter.manifest")
wiring = pytest.importorskip("steamos_mounter.wiring")

pytestmark = pytest.mark.rsync

REPO = Path(__file__).resolve().parents[2]
DECK = REPO / "tests" / "fixtures" / "deck"
DATA = REPO / "data"

KEEP_LIST = "/usr/lib/rauc/atomic-update-keep.conf"
DROPIN_DIR = "/etc/atomic-update.conf.d"
OUR_DROPIN = f"{DROPIN_DIR}/steamos-mounter.conf"
UDEV_RULE = "/etc/udev/rules.d/90-steamos-mounter.rules"
REGISTRY = "/etc/steamos-mounter/config.toml"
MEDIABOX_LINK = (
    "/etc/systemd/system/dev-disk-by\\x2duuid-01D95F1575592A30.device.wants/"
    "steamos-mounter@dev-disk-by\\x2duuid-01D95F1575592A30.service"
)


@pytest.fixture
def keep_list_sources() -> dict[str, Path]:
    """Host paths to seed under tmp_path and the file each one is copied from.

    Build: for every (host path, source) copy the source to
    HostPaths(root=tmp_path).p(host path). The registry row of the manifest is
    seeded with a one-entry registry for MEDIABOX so wiring.expected_links
    yields MEDIABOX_LINK.
    """
    return {
        KEEP_LIST: DECK / "atomic-update-keep.conf",
        f"{DROPIN_DIR}/all.conf": DECK / "atomic-update.conf.d-all.conf",
        OUR_DROPIN: DATA / "steamos-mounter.conf",
        "/opt/steamos-mounter/current/data/manifest.tsv": DATA / "manifest.tsv",
    }


# AC-038: "Given a completed SteamOS atomic update, with no owner action, then
#   config, keys, units and the udev rule are still present ... and doctor
#   passes." (the CI half: every installed /etc path is kept by the filter)
# AC-043: "Given an install, then doctor checks every /etc path that
#   steamos-mounter installed against the keep-list globs (the defaults plus the
#   drop-in). It lists any path no glob matches and exits non-zero."
# SM-10: 100% of installed /etc paths covered.
# ROI: 63 (BV:9 x Freq:6 + Legal:0 + Defect:9)
# Behavior: expected set (manifest /etc rows + wants links) -> filter built like
#   holo-sync-var -> scratch src/dst trees -> rsync dry run -> itemize parse ->
#   every expected path covered -> Check "ok"
# @category: core-functionality
# @dependency: doctor, manifest, wiring, config, runner (real rsync)
# @complexity: high
# @real-dependency: /usr/bin/rsync, tmp_path keep-list, drop-ins, manifest,
#   registry, scratch TemporaryDirectory
def test_keep_list_coverage_ok_with_dropin_present(tmp_path: Path) -> None:
    """Positive control: the shipped drop-in covers every installed /etc path.

    Given
      - keep_list_sources seeded under HostPaths(root=tmp_path); the registry
        holds MEDIABOX; expected = manifest.etc_paths(manifest.parse(...))
        plus wiring.expected_links(registry) ({link path: target text})
    When
      - check = doctor.keep_list_coverage(ctx, expected)
    Then (pass criteria)
      - check.status == "ok" and check.needs_root is False
      - the rsync argv the runner recorded is exactly
        /usr/bin/rsync -rlpgoDHA --delete --one-file-system --checksum
        --prune-empty-dirs --dry-run --out-format=%i %n --include=*/
        --include-from=<filter> --exclude=* <scratch>/src/ <scratch>/dst/
        (Design Doc "Command", timeout 30 s)
      - the filter file content equals the keep-list with ^/etc removed per
        line, then for each sorted *.conf drop-in a "\\n" plus that file's
        lines with ^/etc removed (byte-for-byte like holo-sync-var
        build_etc_rsync_config); the filter holds no backslash
      - the scratch tree is removed after the check (no leftover
        steamos-mounter-doctor-* directory in tempfile.gettempdir())
      - the covered set includes OUR_DROPIN, UDEV_RULE, REGISTRY, the three
        unit files and MEDIABOX_LINK (a symlink entry with second itemize
        character "L")
    """
    pytest.skip("skeleton: implement in Phase 5 (doctor); port the replay script")


# AC-043 negative control (Design Doc 3.7: "drop-in removed (negative control)
#   -> the udev rule and registry are reported") and the tripwire ("our drop-in
#   missing -> FAIL 'cannot verify keep-list coverage'").
# ROI: 41 (BV:8 x Freq:4 + Legal:0 + Defect:9)
# Behavior: without our globs the default keep-list leaves the udev rule and the
#   registry uncovered -> FAIL listing them; without the drop-in file at all the
#   tripwire fails closed before rsync runs
# @category: edge-case
# @dependency: doctor, manifest, wiring (real rsync)
# @complexity: medium
# @real-dependency: /usr/bin/rsync, tmp_path keep-list and drop-ins
@pytest.mark.parametrize("dropin", ["comments-only", "missing"])
def test_keep_list_coverage_fails_without_our_globs(
    dropin: str,
    tmp_path: Path,
) -> None:
    """Negative control: FAIL names the uncovered paths, or cannot verify.

    Given
      - the positive-control setup, then: "comments-only": OUR_DROPIN rewritten
        to hold only its two "##" comment lines (the tripwire passes, the
        filter lacks our globs); "missing": OUR_DROPIN deleted
    When
      - check = doctor.keep_list_coverage(ctx, expected)
    Then (pass criteria)
      - check.status == "FAIL" in both cases (AC-043: exits non-zero through
        doctor.run; the exit-code mapping is tests/unit/test_doctor.py)
      - "comments-only": check.detail lists "not kept by SteamOS updates:
        /etc/udev/rules.d/90-steamos-mounter.rules" and the same for
        /etc/steamos-mounter/config.toml; paths the default keep-list already
        keeps (confirm against fixtures/deck/atomic-update-keep.conf, e.g. the
        unit files if /etc/systemd/system/** is a default glob) are not
        listed; rsync ran exactly once
      - "missing": check.detail == "cannot verify keep-list coverage" (or
        starts with it) and rsync did not run (tripwire before the dry run)
    Open question for the designer: the Design Doc's 3.7 wording "drop-in
    removed" conflicts with the tripwire rule; this skeleton treats "removed"
    as the comments-only variant and keeps the tripwire case separate.
    """
    pytest.skip("skeleton: implement in Phase 5 (doctor); port the replay script")
