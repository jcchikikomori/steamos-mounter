"""EVP-1: ``route()`` over the real Deck tree, field by field against the golden file.

Design Doc "Verification Strategy > Early Verification Point" (EVP-1) and
"Device Classification and Routing". Every input is a real capture:

- the device tree is ``lsblk-columns-tree.json``;
- the OS partition set is built by the real SteamOS code from
  ``udev-run-90-holo-partsets-all.rules.txt`` placed at holo's path;
- ``slaves``, ``holders`` and ``dm/name`` come from ``sysfs-facts.txt``
  (through ``parse_sysfs_facts``), the
  sysfs paths from the ``DEVPATH`` lines of the ``udev-*.txt`` captures;
- the registry holds MEDIABOX and PERSONAL, parsed by ``config.parse``.

``tests/fixtures/golden/evp1-routes.json`` was written by hand from the routing
table, not from ``route()`` output. Each golden row names its device by kname
and by UUID; the UUID check keeps the golden honest if a recapture ever lists
the WD drive under another kernel name (it was ``sda`` on 2026-10-09).

A mismatch means a wrong reading of the ADR-0002 rules: fix ``parse_lsblk_json``
or the routing table, never the golden file, unless the Design Doc is revised.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from steamos_mounter.blockdev import DeviceTree, parse_lsblk_json
from steamos_mounter.config import parse
from steamos_mounter.context import Context
from steamos_mounter.model import InstanceKind, Registry
from steamos_mounter.platforms.base import OsPartitionSet
from steamos_mounter.platforms.steamos import HOLO_RULES
from steamos_mounter.routing import Action, Route, RoutingInput, route
from tests.helpers.builders import MEDIABOX, PERSONAL, registry_text
from tests.helpers.fake_platform import FakePlatform
from tests.helpers.fixtures import DECK, FIXTURES, load_fixture
from tests.helpers.host_tree import HostTree, SysfsDevice, parse_sysfs_facts

GOLDEN = FIXTURES / "golden" / "evp1-routes.json"
TREE_FIXTURE = "lsblk-columns-tree.json"
LOCKED_TREE_FIXTURE = "lsblk-tree-personal-locked.json"
RULES_FIXTURE = "udev-run-90-holo-partsets-all.rules.txt"
UDEV_GLOB = "udev-*.txt"
DEVPATH_PREFIX = "DEVPATH="
SYS_ROOT = "/sys"
MOUNT_BASE = "/run/media/deck"
ROUTE_FIELDS = (
    "action",
    "reason",
    "device",
    "volume",
    "path",
    "inner",
    "mapping_name",
    "delegate_unit",
)


def golden() -> dict[str, Any]:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def golden_rows() -> list[dict[str, Any]]:
    return golden()["routes"]


def row_id(row: Mapping[str, Any]) -> str:
    return f"{row['kind']}-{row['kname']}"


# --- real inputs ------------------------------------------------------------------


def sysfs_facts() -> dict[str, SysfsDevice]:
    """The real ``sysfs-facts.txt`` capture, by kname."""
    return {device.kname: device for device in parse_sysfs_facts()}


def dm_names(facts: Mapping[str, SysfsDevice]) -> dict[str, str]:
    return {
        kname: device.dm_name
        for kname, device in facts.items()
        if device.dm_name is not None
    }


def udev_syspaths(deck: Path) -> dict[str, str]:
    """kname -> ``/sys`` + DEVPATH, from every real ``udev-*.txt`` capture."""
    syspaths: dict[str, str] = {}
    for capture in sorted(deck.glob(UDEV_GLOB)):
        for line in capture.read_text(encoding="utf-8").splitlines():
            if line.startswith(DEVPATH_PREFIX):
                devpath = line.removeprefix(DEVPATH_PREFIX)
                syspaths[devpath.rpartition("/")[2]] = SYS_ROOT + devpath
    return syspaths


def os_partitions(host_tree: HostTree, ctx: Context) -> OsPartitionSet:
    """The real SteamOS reader over holo's real rules file (deck view)."""
    rules = host_tree.path(HOLO_RULES)
    rules.parent.mkdir(parents=True)
    rules.write_bytes(load_fixture(RULES_FIXTURE))
    return FakePlatform().os_partitions(ctx, as_root=False)


def evp1_registry() -> Registry:
    return parse(registry_text([MEDIABOX, PERSONAL]), mount_base=MOUNT_BASE)


def routing_input(
    kind: str, kname: str, tree: DeviceTree, os_parts: OsPartitionSet
) -> RoutingInput:
    facts = sysfs_facts()
    device = facts.get(kname, SysfsDevice(kname=kname))
    return RoutingInput(
        kind=InstanceKind(kind),
        kname=kname,
        tree=tree,
        registry=evp1_registry(),
        os_parts=os_parts,
        slaves=device.slaves,
        holders=device.holders,
        dm_names=dm_names(facts),
        syspaths=udev_syspaths(DECK),
        platform=FakePlatform(),
    )


def as_row(found: Route) -> dict[str, Any]:
    """The golden file's view of a ``Route``: devices by kname, volume by name."""
    return {
        "action": str(found.action),
        "reason": found.reason,
        "device": found.device.kname if found.device else None,
        "volume": found.volume.name if found.volume else None,
        "path": found.volume.path if found.volume else None,
        "inner": found.inner.kname if found.inner else None,
        "mapping_name": found.mapping_name,
        "delegate_unit": found.delegate_unit,
    }


# --- the golden file itself -------------------------------------------------------


def test_golden_covers_every_device_of_the_real_tree_on_the_auto_path():
    tree = parse_lsblk_json(load_fixture(TREE_FIXTURE))
    auto_knames = [row["kname"] for row in golden_rows() if row["kind"] == "auto"]

    assert sorted(auto_knames) == sorted(tree.devices)


def test_golden_has_one_registered_row_per_registry_volume():
    registered = {
        row["volume"]: row["kname"]
        for row in golden_rows()
        if row["kind"] == "registered"
    }

    assert registered == {"MEDIABOX": "sdb5", "PERSONAL": "sdb1"}


def test_real_os_set_is_known_and_comes_from_the_holo_rules(host_tree, ctx_deck):
    found = os_partitions(host_tree, ctx_deck)

    assert found.known is True
    assert found.sources == (HOLO_RULES,)
    assert len(found.partuuids) == 8


def test_real_sysfs_inputs_match_the_capture():
    facts = sysfs_facts()

    assert facts["dm-0"].slaves == ("sdb1",)
    assert facts["sdb1"].holders == ("dm-0",)
    assert facts["sdb5"].holders == ()
    assert dm_names(facts) == {"dm-0": "PAT4T4SHUAWEI_PERSONAL_4_3_2024"}
    assert udev_syspaths(DECK)["sdb1"] == (
        "/sys/devices/pci0000:00/0000:00:08.1/0000:04:00.3/usb2/2-1/2-1.1/"
        "2-1.1:1.0/host1/target1:0:0/1:0:0:0/block/sdb/sdb1"
    )


# --- EVP-1 ------------------------------------------------------------------------


@pytest.mark.parametrize("row", golden_rows(), ids=row_id)
def test_golden_row_names_the_device_by_uuid(row):
    tree = parse_lsblk_json(load_fixture(TREE_FIXTURE))

    assert tree.devices[row["kname"]].uuid == row["uuid"]


@pytest.mark.parametrize("row", golden_rows(), ids=row_id)
def test_evp1_route_matches_golden_field_by_field(row, host_tree, ctx_deck):
    tree = parse_lsblk_json(load_fixture(TREE_FIXTURE))
    inp = routing_input(
        row["kind"], row["kname"], tree, os_partitions(host_tree, ctx_deck)
    )

    found = as_row(route(inp))

    for field in ROUTE_FIELDS:
        assert found[field] == row[field], f"{row_id(row)}: field {field}"


def test_evp1_success_list(host_tree, ctx_deck):
    # The EVP-1 bullets that hold for the tree as captured (dm-0 open).
    tree = parse_lsblk_json(load_fixture(TREE_FIXTURE))
    os_parts = os_partitions(host_tree, ctx_deck)

    def action(kind: str, kname: str) -> Action:
        return route(routing_input(kind, kname, tree, os_parts)).action

    assert action("registered", "sdb5") is Action.MOUNT_REGISTERED
    assert action("auto", "sdb5") is Action.YIELD
    assert action("auto", "sdb1") is Action.YIELD
    assert action("auto", "dm-0") is Action.DELEGATE
    ignored = ["sda1", "mmcblk0p1", "sdb2"] + [f"nvme0n1p{n}" for n in range(1, 9)]
    assert {kname: action("auto", kname) for kname in ignored} == dict.fromkeys(
        ignored, Action.IGNORE
    )


def test_locked_personal_registered_routes_to_unlock(host_tree, ctx_deck):
    # EVP-1's "sdb1 registered -> UNLOCK_REGISTERED" needs the container locked:
    # the synthetic tree is the real one minus dm-0, and sdb1 has no holders.
    tree = parse_lsblk_json(load_fixture(LOCKED_TREE_FIXTURE))
    inp = routing_input("registered", "sdb1", tree, os_partitions(host_tree, ctx_deck))
    locked = RoutingInput(
        kind=inp.kind,
        kname=inp.kname,
        tree=inp.tree,
        registry=inp.registry,
        os_parts=inp.os_parts,
        slaves=(),
        holders=(),
        dm_names={},
        syspaths=inp.syspaths,
        platform=inp.platform,
    )

    found = route(locked)

    assert found.action is Action.UNLOCK_REGISTERED
    assert found.volume is not None
    assert found.volume.name == "PERSONAL"
    assert found.inner is None
