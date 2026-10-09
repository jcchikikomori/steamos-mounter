"""Unit tests for steamos_mounter.sensitive.

Design Doc: docs/design/steamos-mounter-design.md (sections "Module
Responsibilities and Public Interfaces > errors, output, sensitive" and
"Logging and Secret Handling", rule 6: text, representation and format output
are ``<secret redacted>``; pickling raises). ADR-COMMON-0001 decision 4:
redaction replaces every secret that is live in the process.

Real byte values, no fakes. Assertions that involve a secret compare
booleans computed beforehand, so a failing test never prints the bytes.
"""

import copy
import gc
import pickle
from collections.abc import Callable, Iterator

import pytest

from steamos_mounter.sensitive import SecretBytes, live_secrets, redact_text

PLACEHOLDER = "<secret redacted>"
REDACTED = "[REDACTED]"
TEST_KEY = b"TEST-KEY-7f3a9c-do-not-leak"
# BitLocker recovery-key shape: eight groups of six digits.
RECOVERY_KEY = b"123456-234567-345678-456789-567890-678901-789012-890123"

SecretFactory = Callable[..., SecretBytes]


@pytest.fixture
def make_secret() -> Iterator[SecretFactory]:
    """Creates secrets and clears every one at teardown, so none stays live."""
    created: list[SecretBytes] = []

    def factory(data: bytes | bytearray, **kwargs: str) -> SecretBytes:
        secret = SecretBytes(data, **kwargs)
        created.append(secret)
        return secret

    yield factory
    for secret in created:
        secret.clear()


def buffers_of(secret: SecretBytes) -> list[bytearray]:
    """The bytearray objects the wrapper holds, found without private names."""
    return [ref for ref in gc.get_referents(secret) if isinstance(ref, bytearray)]


def test_reveal_returns_exact_bytes_and_input_buffer_is_copied(make_secret):
    source = bytearray(RECOVERY_KEY)
    secret = make_secret(source, label="recovery")

    source[:] = bytes(len(source))
    revealed_matches = secret.reveal() == RECOVERY_KEY

    assert revealed_matches
    assert isinstance(secret.reveal(), bytes)
    assert len(secret) == 55
    assert secret.label == "recovery"
    assert make_secret(TEST_KEY).label == "key"


@pytest.mark.parametrize(
    "data",
    ["TEST-KEY-as-text", 27, [84, 69], memoryview(b"view"), None],
    ids=["str", "int", "list", "memoryview", "none"],
)
def test_constructor_rejects_anything_but_bytes_or_bytearray(data):
    with pytest.raises(TypeError, match="bytes or bytearray"):
        SecretBytes(data)

    assert len(live_secrets()) == 0


@pytest.mark.parametrize(
    "render",
    [
        str,
        repr,
        format,
        lambda secret: format(secret, ">40"),
        lambda secret: f"{secret}",
        lambda secret: f"{secret!r}",
        lambda secret: "%s" % secret,  # noqa: UP031
        lambda secret: "{}".format(secret),  # noqa: UP032
        lambda secret: repr([secret]).strip("[]"),
    ],
    ids=[
        "str",
        "repr",
        "format",
        "format-spec",
        "fstr",
        "fstr-r",
        "percent",
        "str-format",
        "container",
    ],
)
def test_every_text_form_is_the_placeholder(make_secret, render):
    secret = make_secret(TEST_KEY)

    assert render(secret) == PLACEHOLDER


@pytest.mark.parametrize(
    "convert",
    [pickle.dumps, copy.copy, copy.deepcopy, bytes],
    ids=["pickle", "copy", "deepcopy", "bytes"],
)
def test_pickling_copying_and_bytes_conversion_raise_type_error(make_secret, convert):
    secret = make_secret(TEST_KEY)

    with pytest.raises(TypeError):
        convert(secret)


def test_live_secrets_lists_every_live_value_in_creation_order(make_secret):
    make_secret(TEST_KEY)
    make_secret(bytearray(RECOVERY_KEY))

    listed = live_secrets()
    matches = listed == (TEST_KEY, RECOVERY_KEY)

    assert matches
    assert all(type(value) is bytes for value in listed)


def test_clear_zeroes_in_place_unregisters_and_blocks_reveal(make_secret):
    secret = make_secret(RECOVERY_KEY)
    (held,) = buffers_of(secret)

    secret.clear()
    secret.clear()

    assert held == bytearray(55)
    assert len(secret) == 0
    assert len(live_secrets()) == 0
    with pytest.raises(ValueError, match="cleared"):
        secret.reveal()


def test_context_manager_returns_itself_and_clears_on_exit_even_on_error():
    with SecretBytes(TEST_KEY) as secret:
        assert len(live_secrets()) == 1
    assert len(secret) == 0
    assert len(live_secrets()) == 0

    with (
        pytest.raises(RuntimeError, match="boom"),
        SecretBytes(RECOVERY_KEY) as failing,
    ):
        raise RuntimeError("boom")
    assert len(failing) == 0
    assert len(live_secrets()) == 0


@pytest.mark.parametrize(
    ("secrets", "text", "expected"),
    [
        (
            (TEST_KEY, RECOVERY_KEY),
            f"key={TEST_KEY.decode()} recovery={RECOVERY_KEY.decode()} again "
            f"{TEST_KEY.decode()}",
            f"key={REDACTED} recovery={REDACTED} again {REDACTED}",
        ),
        ((b"abc", b"abcdef"), "x abcdef y abc", f"x {REDACTED} y {REDACTED}"),
        ((b"pass\xffword",), "got pass\udcffword", f"got {REDACTED}"),
        ((b"", TEST_KEY), "nothing secret here", "nothing secret here"),
        ((TEST_KEY,), "", ""),
    ],
    ids=["two-live-secrets", "longest-first", "non-utf8", "empty-secret", "empty-text"],
)
def test_redact_text_replaces_every_live_secret(make_secret, secrets, text, expected):
    for data in secrets:
        make_secret(data)

    redacted = redact_text(text)
    matches = redacted == expected

    assert matches


def test_redact_text_stops_redacting_a_secret_after_clear(make_secret):
    cleared = make_secret(TEST_KEY)
    make_secret(RECOVERY_KEY)
    text = f"{TEST_KEY.decode()} | {RECOVERY_KEY.decode()}"

    cleared.clear()
    redacted = redact_text(text)
    matches = redacted == f"{TEST_KEY.decode()} | {REDACTED}"

    assert matches
