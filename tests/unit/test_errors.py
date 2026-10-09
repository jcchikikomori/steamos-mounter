"""Unit tests for steamos_mounter.errors.

Design Doc: docs/design/steamos-mounter-design.md (sections "Module
Responsibilities and Public Interfaces > errors, output, sensitive" and
"CLI Contract > Exit Codes"). ADR-COMMON-0001 decision 8: the terminal gets
the short generic message; the detail goes to the journal only.
"""

import pytest

from steamos_mounter.errors import (
    ExitCode,
    InvalidKernelName,
    MounterError,
    NeedsRootError,
    NotPresentError,
    RefusedError,
    RegistryError,
    SecretHandlingError,
    ToolError,
    UnsupportedPlatformError,
    UsageError,
)

# The Exit Codes table of the Design Doc, written out independently.
EXIT_CODE_TABLE = {
    "OK": 0,
    "FAILED": 1,
    "USAGE": 2,
    "NEEDS_ROOT": 3,
    "UNSUPPORTED_PLATFORM": 4,
    "PARTIAL": 5,
    "BUSY": 6,
    "NOT_PRESENT": 7,
    "REFUSED": 8,
}


def test_exit_code_members_match_the_design_table():
    assert {member.name: member.value for member in ExitCode} == EXIT_CODE_TABLE


def test_exit_code_is_an_int_usable_as_process_status():
    assert ExitCode.REFUSED == 8
    assert int(ExitCode.NOT_PRESENT) == 7


@pytest.mark.parametrize(
    ("error_class", "expected_code"),
    [
        (MounterError, 1),
        (UsageError, 2),
        (NeedsRootError, 3),
        (UnsupportedPlatformError, 4),
        (NotPresentError, 7),
        (RefusedError, 8),
        (RegistryError, 1),
        (ToolError, 1),
        (InvalidKernelName, 1),
    ],
)
def test_each_error_carries_its_exit_code(error_class, expected_code):
    assert error_class.exit_code == expected_code
    assert error_class("failed").exit_code == expected_code


@pytest.mark.parametrize(
    "error_class",
    [
        UsageError,
        NeedsRootError,
        UnsupportedPlatformError,
        NotPresentError,
        RefusedError,
        RegistryError,
        ToolError,
        InvalidKernelName,
    ],
)
def test_every_domain_error_is_caught_as_mounter_error(error_class):
    with pytest.raises(MounterError) as caught:
        raise error_class("volume MEDIABOX is not attached")

    assert caught.value.user_message == "volume MEDIABOX is not attached"


def test_mounter_error_keeps_message_detail_and_volume():
    error = MounterError(
        "mount failed",
        detail="ntfs3: volume is dirty and force flag is not set",
        volume="MEDIABOX",
    )

    assert error.user_message == "mount failed"
    assert error.detail == "ntfs3: volume is dirty and force flag is not set"
    assert error.volume == "MEDIABOX"


def test_mounter_error_defaults_to_no_detail_and_no_volume():
    error = MounterError("registry unusable")

    assert error.detail == ""
    assert error.volume is None


def test_str_shows_only_the_generic_message_never_the_detail():
    error = ToolError("unlock failed", detail="cryptsetup exited 2: stderr text")

    assert str(error) == "unlock failed"
    assert "cryptsetup" not in str(error)


def test_detail_and_volume_are_keyword_only():
    with pytest.raises(TypeError):
        MounterError("mount failed", "detail given positionally")


def test_secret_handling_error_is_a_programming_error_not_a_domain_error():
    error = SecretHandlingError("secret reached argv")

    assert isinstance(error, RuntimeError)
    assert not isinstance(error, MounterError)
