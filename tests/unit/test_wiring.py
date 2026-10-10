"""wiring: one ``.device.wants`` link per registered volume, regenerated.

Design Doc "session, dialog, notify, systemd, wiring" (``TEMPLATE_PATH``,
``expected_links``, ``existing_links``, ``WiringChange``, ``sync_links``),
"Interface Change Matrix" (instance naming), "Keep-list Drop-in" (the wants
link pattern), IP-02 and NFR-25; ADR-0002 D1 and D6.2 (create the missing
links, remove the ones no registered volume needs). The link tree is real
files under ``tmp_path``; the expected names are written out by hand from
``systemd-escape --path``, not computed with the package's escaper.
"""

import os
from pathlib import Path

import pytest

from steamos_mounter import wiring
from steamos_mounter.config import parse
from steamos_mounter.errors import MounterError
from steamos_mounter.model import InvalidEntry, Registry
from tests.helpers.builders import MEDIABOX, PERSONAL, many_volumes, registry_text

SYSTEMD_DIR = "/etc/systemd/system"
TEMPLATE = "/etc/systemd/system/steamos-mounter@.service"
MEDIABOX_WANTS = (
    "/etc/systemd/system/dev-disk-by\\x2duuid-01D95F1575592A30.device.wants"
)
MEDIABOX_LINK = (
    f"{MEDIABOX_WANTS}/steamos-mounter@dev-disk-by\\x2duuid-01D95F1575592A30.service"
)
PERSONAL_WANTS = (
    "/etc/systemd/system/dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52"
    "\\x2da297\\x2d31643c64724d.device.wants"
)
PERSONAL_LINK = (
    f"{PERSONAL_WANTS}/steamos-mounter@dev-disk-by\\x2duuid-658207d5\\x2d5177"
    "\\x2d4a52\\x2da297\\x2d31643c64724d.service"
)
OLD_UUID_WANTS = "/etc/systemd/system/dev-disk-by\\x2duuid-1234\\x2dABCD.device.wants"
OLD_UUID_LINK = (
    f"{OLD_UUID_WANTS}/steamos-mounter@dev-disk-by\\x2duuid-1234\\x2dABCD.service"
)
TWO_VOLUMES = parse(registry_text([MEDIABOX, PERSONAL]))
EMPTY = Registry(schema_version=1, volumes=(), invalid=())
NFR_25_VOLUMES = 50


def host(root: Path, absolute: str) -> Path:
    return root / absolute.lstrip("/")


def plant_link(root: Path, absolute: str, target: str = TEMPLATE) -> Path:
    path = host(root, absolute)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)
    return path


@pytest.fixture
def units_installed(tmp_path: Path) -> Path:
    """``/etc/systemd/system``, where the installer has written the units."""
    directory = host(tmp_path, SYSTEMD_DIR)
    directory.mkdir(parents=True)
    return directory


def test_template_path_is_the_installed_registered_unit():
    assert wiring.TEMPLATE_PATH == TEMPLATE


def test_expected_links_name_one_link_per_volume_after_its_by_uuid_path():
    assert wiring.expected_links(TWO_VOLUMES) == {
        MEDIABOX_LINK: TEMPLATE,
        PERSONAL_LINK: TEMPLATE,
    }


def test_expected_links_keep_the_uuid_case_of_the_by_uuid_link():
    links = wiring.expected_links(parse(registry_text([MEDIABOX])))

    assert list(links) == [MEDIABOX_LINK]
    assert "01d95f1575592a30" not in MEDIABOX_LINK


def test_an_empty_registry_needs_no_link():
    assert wiring.expected_links(EMPTY) == {}


def test_an_invalid_entry_with_a_uuid_keeps_its_link_so_its_instance_can_refuse():
    registry = Registry(
        schema_version=1,
        volumes=(),
        invalid=(
            InvalidEntry(0, "01D95F1575592A30", "path must be directly under"),
            InvalidEntry(1, None, "uuid: not a valid UUID"),
        ),
    )

    assert wiring.expected_links(registry) == {MEDIABOX_LINK: TEMPLATE}


def test_fifty_volumes_give_fifty_distinct_links_with_no_limit():
    registry = parse(registry_text(many_volumes(NFR_25_VOLUMES)))

    links = wiring.expected_links(registry)

    assert len(registry.volumes) == NFR_25_VOLUMES
    assert len(links) == NFR_25_VOLUMES
    assert set(links.values()) == {TEMPLATE}


def test_existing_links_on_a_host_without_the_unit_directory_are_none(ctx):
    assert wiring.existing_links(ctx) == {}


def test_existing_links_read_only_this_tools_links_in_device_wants_dirs(ctx, tmp_path):
    plant_link(tmp_path, MEDIABOX_LINK)
    plant_link(tmp_path, OLD_UUID_LINK, "/somewhere/else.service")
    plant_link(tmp_path, f"{MEDIABOX_WANTS}/other@x.service")
    plant_link(
        tmp_path, f"{SYSTEMD_DIR}/multi-user.target.wants/steamos-mounter@x.service"
    )
    host(tmp_path, f"{PERSONAL_WANTS}/steamos-mounter@not-a-link.service").parent.mkdir(
        parents=True
    )
    host(tmp_path, f"{PERSONAL_WANTS}/steamos-mounter@not-a-link.service").touch()

    assert wiring.existing_links(ctx) == {
        MEDIABOX_LINK: TEMPLATE,
        OLD_UUID_LINK: "/somewhere/else.service",
    }


def test_existing_links_skip_a_wants_name_that_is_not_a_real_directory(ctx, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    plant_link(tmp_path, "/elsewhere/steamos-mounter@x.service")
    host(tmp_path, SYSTEMD_DIR).mkdir(parents=True)
    host(tmp_path, f"{SYSTEMD_DIR}/dev-x.device.wants").symlink_to(elsewhere)
    host(tmp_path, f"{SYSTEMD_DIR}/dev-y.device.wants").touch()

    assert wiring.existing_links(ctx) == {}


def test_sync_creates_every_missing_link_pointing_at_the_template(
    units_installed, ctx, tmp_path
):
    change = wiring.sync_links(ctx, TWO_VOLUMES)

    assert change == wiring.WiringChange(
        created=(MEDIABOX_LINK, PERSONAL_LINK), removed=()
    )
    assert os.readlink(host(tmp_path, MEDIABOX_LINK)) == TEMPLATE
    assert os.readlink(host(tmp_path, PERSONAL_LINK)) == TEMPLATE
    assert (host(tmp_path, MEDIABOX_WANTS).stat().st_mode & 0o777) == 0o755


def test_sync_removes_a_stale_link_and_its_emptied_wants_directory(ctx, tmp_path):
    plant_link(tmp_path, MEDIABOX_LINK)
    plant_link(tmp_path, OLD_UUID_LINK)

    change = wiring.sync_links(ctx, parse(registry_text([MEDIABOX])))

    assert change == wiring.WiringChange(created=(), removed=(OLD_UUID_LINK,))
    assert not os.path.lexists(host(tmp_path, OLD_UUID_LINK))
    assert not os.path.lexists(host(tmp_path, OLD_UUID_WANTS))
    assert os.readlink(host(tmp_path, MEDIABOX_LINK)) == TEMPLATE


def test_sync_keeps_a_wants_directory_another_unit_still_uses(ctx, tmp_path):
    plant_link(tmp_path, OLD_UUID_LINK)
    other = plant_link(tmp_path, f"{OLD_UUID_WANTS}/other@x.service")

    change = wiring.sync_links(ctx, EMPTY)

    assert change.removed == (OLD_UUID_LINK,)
    assert os.path.lexists(other)


def test_sync_both_ways_at_once(ctx, tmp_path):
    plant_link(tmp_path, OLD_UUID_LINK)

    change = wiring.sync_links(ctx, TWO_VOLUMES)

    assert change == wiring.WiringChange(
        created=(MEDIABOX_LINK, PERSONAL_LINK), removed=(OLD_UUID_LINK,)
    )
    assert set(wiring.existing_links(ctx)) == {MEDIABOX_LINK, PERSONAL_LINK}


def test_sync_replaces_a_link_with_another_target(ctx, tmp_path):
    plant_link(tmp_path, MEDIABOX_LINK, "/usr/lib/systemd/system/other.service")

    change = wiring.sync_links(ctx, parse(registry_text([MEDIABOX])))

    assert change == wiring.WiringChange(created=(MEDIABOX_LINK,), removed=())
    assert os.readlink(host(tmp_path, MEDIABOX_LINK)) == TEMPLATE


def test_sync_twice_changes_nothing_the_second_time(units_installed, ctx):
    wiring.sync_links(ctx, TWO_VOLUMES)

    assert wiring.sync_links(ctx, TWO_VOLUMES) == wiring.WiringChange((), ())


def test_sync_of_fifty_volumes_writes_fifty_links(units_installed, ctx):
    registry = parse(registry_text(many_volumes(NFR_25_VOLUMES)))

    change = wiring.sync_links(ctx, registry)

    assert len(change.created) == NFR_25_VOLUMES
    assert len(wiring.existing_links(ctx)) == NFR_25_VOLUMES


def test_sync_refuses_a_wants_name_that_is_not_a_directory(ctx, tmp_path):
    host(tmp_path, MEDIABOX_WANTS).parent.mkdir(parents=True)
    host(tmp_path, MEDIABOX_WANTS).symlink_to(tmp_path)

    with pytest.raises(MounterError) as raised:
        wiring.sync_links(ctx, parse(registry_text([MEDIABOX])))

    assert MEDIABOX_WANTS in raised.value.detail
    assert not os.path.lexists(tmp_path / os.path.basename(MEDIABOX_LINK))


def test_sync_propagates_a_failed_removal(ctx, tmp_path, monkeypatch):
    plant_link(tmp_path, OLD_UUID_LINK)

    def refuse(_path: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(wiring.os, "rmdir", refuse)

    with pytest.raises(PermissionError):
        wiring.sync_links(ctx, EMPTY)
