"""Registry round trip: ``parse(emit(r)) == r`` for generated registries.

Design Doc "Registry > Emitter" and "Test Strategy > Property" item 2. The
generated registries are valid by construction: names from the registry name
rule, UUIDs in all three schema forms, every filesystem type, ``drivers``
lists only where the schema allows them, both values of ``nosuid`` and
``nodev``, and up to 60 volumes (NFR-25 has no count limit). Names and UUIDs
are unique case-insensitively, and each path is the mount base child named
after its volume (rule 9, DD-34), so no two paths are equal or nest.

Runs are reproducible: a fixed seed, ``derandomize=True`` and no example
database, so CI and a laptop see the same examples.
"""

from hypothesis import given, seed, settings
from hypothesis import strategies as st

from steamos_mounter.config import emit, parse
from steamos_mounter.model import Driver, Mode, Registry, Step, Volume
from steamos_mounter.naming import REGISTRY_NAME_RE

MOUNT_BASE = "/run/media/deck"
SEED = 20261009
DRIVERS_FSTYPES = ("ntfs", "BitLocker")
OTHER_FSTYPES = ("exfat", "vfat", "btrfs")
NTFS_STEPS = tuple(
    Step(driver, mode)
    for driver in (Driver.NTFS3, Driver.NTFS3G, Driver.NTFS)
    for mode in Mode
)
UUID_PATTERNS = (
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}",
    r"[0-9A-Fa-f]{16}",
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
)

PROPERTY_SETTINGS = settings(
    derandomize=True, database=None, max_examples=200, deadline=None
)

names = st.from_regex(REGISTRY_NAME_RE, fullmatch=True)
uuids = st.one_of(
    *(st.from_regex(pattern, fullmatch=True) for pattern in UUID_PATTERNS)
)
drivers = st.none() | st.lists(
    st.sampled_from(NTFS_STEPS), min_size=1, unique=True
).map(tuple)


@st.composite
def volumes(draw: st.DrawFn) -> Volume:
    name = draw(names)
    if draw(st.booleans()):
        fstype = draw(st.sampled_from(DRIVERS_FSTYPES))
        steps = draw(drivers)
    else:
        fstype = draw(st.sampled_from(OTHER_FSTYPES))
        steps = None
    return Volume(
        name=name,
        uuid=draw(uuids),
        path=f"{MOUNT_BASE}/{name}",
        fstype=fstype,
        drivers=steps,
        nosuid=draw(st.booleans()),
        nodev=draw(st.booleans()),
    )


registries = st.lists(
    volumes(),
    max_size=60,
    unique_by=(
        lambda volume: volume.name.casefold(),
        lambda volume: volume.uuid.lower(),
    ),
).map(
    lambda items: Registry(
        schema_version=1,
        volumes=tuple(sorted(items, key=lambda volume: volume.name)),
        invalid=(),
    )
)


@seed(SEED)
@PROPERTY_SETTINGS
@given(registries)
def test_parse_of_emit_is_identity(registry):
    assert parse(emit(registry), mount_base=MOUNT_BASE) == registry


@seed(SEED)
@PROPERTY_SETTINGS
@given(registries)
def test_parse_without_a_mount_base_is_identity(registry):
    """``parse(text)`` without the platform's base keeps every base child."""
    assert parse(emit(registry)) == registry


@seed(SEED)
@PROPERTY_SETTINGS
@given(registries)
def test_emit_is_stable_across_a_round_trip(registry):
    text = emit(registry)

    assert emit(parse(text, mount_base=MOUNT_BASE)) == text
