"""Hostile-label properties of auto names, registry names and auto paths.

Design Doc "Test Strategy > Property" item 1 and "Names and Paths"; PRD
AC-027 (no ``/``, no ``..``, no NUL or control characters, always a direct
child of the base), AC-028 (never a taken path) and AC-029 (non-empty name).

Labels are drawn from arbitrary Unicode with surrogates included (an
undecodable lsblk byte arrives as one, DD-01), mixed with the fragments that
break naive code: ``/``, ``..``, NUL, controls, ``U+202E``, literal ``\\xNN``
text, leading ``-`` and ``.``, and strings up to 1000 characters.

Runs are reproducible: a fixed seed, ``derandomize=True`` and no example
database, so CI and a laptop see the same examples.
"""

import posixpath
import unicodedata

import pytest
from hypothesis import given, seed, settings
from hypothesis import strategies as st

from steamos_mounter.naming import (
    AUTO_NAME_MAX_BYTES,
    REGISTRY_NAME_RE,
    NoFreeNameError,
    fallback_name,
    propose_registry_name,
    sanitize_label,
    unique_auto_path,
)

BASE = "/run/media/deck"
FALLBACK = "ntfs-01D95F1575592A30"
SEED = 20261009
HOSTILE_FRAGMENTS = (
    "/",
    "\\",
    ".",
    "..",
    "../",
    "-",
    "_",
    " ",
    "\x00",
    "\n",
    "\x7f",
    "\u202e",
    "\u200b",
    "\ufeff",
    "\udcc3",
    r"\xc3\x89",
    "é",
    "e\u0301",
    "PAT4T4SHUAWEI PERSONAL 4/3/2024",
)

PROPERTY_SETTINGS = settings(
    derandomize=True, database=None, max_examples=400, deadline=None
)

any_character = st.characters(codec=None, exclude_categories=())
labels = st.one_of(
    st.none(),
    st.text(any_character, max_size=1000),
    st.lists(
        st.one_of(
            st.sampled_from(HOSTILE_FRAGMENTS), st.text(any_character, max_size=8)
        ),
        max_size=60,
    ).map("".join),
)


def is_safe_component(name: str) -> bool:
    return (
        "/" not in name
        and "\\" not in name
        and name not in {".", ".."}
        and not any(unicodedata.category(char).startswith("C") for char in name)
        and len(name.encode("utf-8")) <= AUTO_NAME_MAX_BYTES
    )


@seed(SEED)
@PROPERTY_SETTINGS
@given(labels)
def test_sanitized_label_is_a_safe_component(label: str | None):
    name = sanitize_label(label)

    assert is_safe_component(name)


@seed(SEED)
@PROPERTY_SETTINGS
@given(labels)
def test_sanitize_label_is_idempotent(label: str | None):
    name = sanitize_label(label)

    assert sanitize_label(name) == name


@seed(SEED)
@PROPERTY_SETTINGS
@given(labels, st.sampled_from(["vfat", "exfat", "ntfs", "BitLocker", None]))
def test_auto_path_is_a_direct_child_of_the_base(label: str | None, fstype: str | None):
    name = sanitize_label(label) or fallback_name(fstype, None, "sdc1")

    path = unique_auto_path(BASE, name, set().__contains__)

    assert name != ""
    assert posixpath.dirname(path) == BASE
    assert posixpath.basename(path) == name
    assert posixpath.normpath(path) == path


@seed(SEED)
@PROPERTY_SETTINGS
@given(
    st.text(any_character, max_size=40),
    st.one_of(st.none(), st.text(any_character, max_size=60)),
)
def test_fallback_name_is_a_safe_component(fstype: str, uuid: str | None):
    name = fallback_name(fstype, uuid, "sdc1")

    assert name != ""
    assert is_safe_component(name)


@seed(SEED)
@PROPERTY_SETTINGS
@given(labels)
def test_registry_proposal_matches_the_registry_regex(label: str | None):
    proposal = propose_registry_name(label, fallback=FALLBACK)

    assert REGISTRY_NAME_RE.fullmatch(proposal)


@seed(SEED)
@PROPERTY_SETTINGS
@given(
    st.sampled_from(
        ["GAMES", "vfat-C40C-B21F", "MÉDIA", "PAT4T4SHUAWEI PERSONAL 4_3_2024"]
    ),
    # At most 98 of the 99 candidates are taken, so one is always free.
    st.sets(st.integers(min_value=1, max_value=99), max_size=98),
)
def test_unique_auto_path_never_returns_a_taken_path(
    name: str, taken_numbers: set[int]
):
    # 1 stands for the bare name; 2 to 99 for the suffixed ones.
    candidates = [f"{BASE}/{name}"] + [f"{BASE}/{name}-{n}" for n in range(2, 100)]
    taken = {candidates[number - 1] for number in taken_numbers}

    path = unique_auto_path(BASE, name, taken.__contains__)

    assert path not in taken
    assert path in candidates
    assert posixpath.dirname(path) == BASE


@seed(SEED)
@PROPERTY_SETTINGS
@given(st.sampled_from(["GAMES", "vfat-C40C-B21F", "MÉDIA"]))
def test_unique_auto_path_raises_when_every_candidate_is_taken(name: str):
    with pytest.raises(NoFreeNameError):
        unique_auto_path(BASE, name, lambda _candidate: True)
