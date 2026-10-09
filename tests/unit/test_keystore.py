"""The key store: input, permission checks, atomic 0600 storage, removal.

Design Doc "Key Store", "Module Responsibilities > keystore", DD-18 (bad
permissions -> no use, point to ``doctor``) and IP-20; ADR-0004 D4; PRD
AC-011 (layout and modes), AC-012 (hidden prompt, never echoed) and AC-057
(exactly one line ending stripped).

Files are real files under ``tmp_path`` owned by the test uid, which is the
``FakePlatform``'s ``trusted_uid``; a wrong owner is a ``trusted_uid`` that is
not the test uid. Key bytes are compared as booleans computed before the
assertion, so a failing test never prints them.
"""

import dataclasses
import getpass
import io
import os
import stat

import pytest

from steamos_mounter import keystore
from steamos_mounter.errors import ExitCode, MounterError, UsageError
from steamos_mounter.keystore import (
    KEY_CAP_CLI,
    KeyStatus,
    delete,
    key_path,
    read_key_input,
    status,
    store,
    strip_one_line_ending,
)
from steamos_mounter.sensitive import SecretBytes, live_secrets

UUID = "658207d5-5177-4a52-a297-31643c64724d"
KEYS = "var/lib/steamos-mounter/keys"
KEY = b"unit-test-key-bytes"
PROMPT = "BitLocker key for PERSONAL: "
NO_TERMINAL = (
    "no terminal for the hidden key prompt. Use --key-file PATH or --key-stdin"
)
INVALID_KEY = "the key must be 1 to 1024 bytes with no NUL byte"
UNREADABLE_FILE = "cannot read the key file"
UNREADABLE_STDIN = "cannot read the key from stdin"
SOURCES = ("file", "stdin")


@pytest.fixture
def keys_dir(tmp_path):
    directory = tmp_path / KEYS
    directory.mkdir(parents=True)
    directory.chmod(0o700)
    return directory


@pytest.fixture
def secret():
    wrapped = SecretBytes(KEY)
    yield wrapped
    wrapped.clear()


def write_key(keys_dir, data: bytes = KEY, *, mode: int = 0o600):
    path = keys_dir / f"{UUID}.key"
    path.write_bytes(data)
    path.chmod(mode)
    return path


def read_from(source: str, data: bytes, tmp_path) -> SecretBytes:
    """``read_key_input`` from a real file or a stdin stream holding ``data``."""
    file_path = None
    stdin = io.BytesIO(b"")
    if source == "file":
        key_file = tmp_path / "typed.key"
        key_file.write_bytes(data)
        file_path = str(key_file)
    else:
        stdin = io.BytesIO(data)
    return read_key_input(
        source=source,
        prompt_text=PROMPT,
        file_path=file_path,
        stdin=stdin,
        tty_prompt=refuse_prompt,
    )


def refuse_prompt(_text: str) -> str:
    raise AssertionError("the prompt must not be used for this source")


def prompt_returning(text: str):
    prompts: list[str] = []

    def prompt(shown: str) -> str:
        prompts.append(shown)
        return text

    return prompt, prompts


def read_prompt(tty_prompt, stdin: io.BytesIO | None = None) -> SecretBytes:
    return read_key_input(
        source="prompt",
        prompt_text=PROMPT,
        file_path=None,
        stdin=stdin or io.BytesIO(b""),
        tty_prompt=tty_prompt,
    )


def holds(wrapped: SecretBytes, expected: bytes) -> bool:
    try:
        return wrapped.reveal() == expected
    finally:
        wrapped.clear()


# --- constants and paths ----------------------------------------------------------


def test_key_cap_is_1024_bytes():
    assert KEY_CAP_CLI == 1024


def test_key_status_values():
    assert [item.value for item in KeyStatus] == ["ok", "missing", "bad-permissions"]


def test_key_path_is_under_var_lib_named_by_uuid(ctx, tmp_path):
    assert key_path(ctx, UUID) == tmp_path / KEYS / f"{UUID}.key"


@pytest.mark.parametrize("uuid", ["01D95F1575592A30", "C40C-B21F"])
def test_key_path_takes_every_registry_uuid_form(ctx, tmp_path, uuid):
    assert key_path(ctx, uuid).name == f"{uuid}.key"


@pytest.mark.parametrize(
    "uuid", ["", "PERSONAL", "../../etc/passwd", f"{UUID}/x", f"{UUID}.key"]
)
def test_key_path_refuses_anything_but_a_uuid(ctx, uuid):
    with pytest.raises(ValueError, match="not a registry UUID"):
        key_path(ctx, uuid)


# --- line endings (AC-057) --------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"abc\n", b"abc"),
        (b"abc\r\n", b"abc"),
        (b"abc\n\n", b"abc\n"),
        (b"abc\r\n\r\n", b"abc\r\n"),
        (b"abc\n\r\n", b"abc\n"),
        (b"abc\r", b"abc\r"),
        (b"abc\n\r", b"abc\n\r"),
        (b"a\nb", b"a\nb"),
        (b"abc", b"abc"),
        (b"\n", b""),
        (b"\r\n", b""),
        (b"", b""),
    ],
)
def test_strip_one_line_ending(data, expected):
    assert strip_one_line_ending(data) == expected


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (KEY + b"\n", KEY),
        (KEY + b"\r\n", KEY),
        (KEY + b"\n\n", KEY + b"\n"),
        (KEY + b"\r\n\r\n", KEY + b"\r\n"),
        (KEY, KEY),
        (b"  spaced key  \n", b"  spaced key  "),
    ],
)
def test_line_ending_stripped_once(tmp_path, source, data, expected):
    wrapped = read_from(source, data, tmp_path)

    assert isinstance(wrapped, SecretBytes)
    assert holds(wrapped, expected)


# --- the hidden prompt (AC-012) ---------------------------------------------------


def test_prompt_not_echoed(monkeypatch, capsys):
    prompts: list[str] = []

    def fake_getpass(prompt: str = "Password: ", stream=None) -> str:
        prompts.append(prompt)
        return "typed key"

    monkeypatch.setattr(getpass, "getpass", fake_getpass)
    stdin = io.BytesIO(b"must not be read")

    wrapped = read_prompt(getpass.getpass, stdin)

    registered = b"typed key" in live_secrets()
    output = capsys.readouterr()
    assert prompts == [PROMPT]
    assert isinstance(wrapped, SecretBytes)
    assert registered
    assert holds(wrapped, b"typed key")
    assert stdin.tell() == 0
    assert (output.out, output.err) == ("", "")


def test_prompt_text_is_kept_as_typed_and_encoded_as_utf8():
    prompt, _ = prompt_returning("cl\u00e9 \t-123456-\r")

    wrapped = read_prompt(prompt)

    assert holds(wrapped, "cl\u00e9 \t-123456-\r".encode())


@pytest.mark.parametrize("error", [OSError(6, "No such device or address"), EOFError()])
def test_prompt_without_a_terminal_is_a_usage_error(error):
    def prompt(_text: str) -> str:
        raise error

    with pytest.raises(UsageError) as raised:
        read_prompt(prompt)

    assert raised.value.user_message == NO_TERMINAL
    assert raised.value.exit_code is ExitCode.USAGE


def test_getpass_fallback_never_reads_stdin_or_warns(capsys):
    """``getpass`` without a terminal would read stdin with echo on; refuse instead."""
    with pytest.raises(UsageError) as raised:
        read_prompt(getpass.fallback_getpass)

    output = capsys.readouterr()
    assert raised.value.user_message == NO_TERMINAL
    assert (output.out, output.err) == ("", "")


def test_prompt_text_that_cannot_be_encoded_is_refused():
    prompt, _ = prompt_returning("bad \ud800 surrogate")

    with pytest.raises(UsageError) as raised:
        read_prompt(prompt)

    assert raised.value.user_message == INVALID_KEY


# --- the three refusals and their boundaries --------------------------------------


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"", "empty"),
        (b"\n", "empty"),
        (b"\r\n", "empty"),
        (b"ab\x00cd", "contains a NUL byte"),
        (b"\x00\n", "contains a NUL byte"),
        (b"a" * (KEY_CAP_CLI + 1), "longer than 1024 bytes"),
        (b"a" * (KEY_CAP_CLI + 1) + b"\r\n", "longer than 1024 bytes"),
        (b"a" * KEY_CAP_CLI + b"\n\n", "longer than 1024 bytes"),
        (b"a" * KEY_CAP_CLI + b"\r\nx", "longer than 1024 bytes"),
        (b"a" * 5000, "longer than 1024 bytes"),
    ],
)
def test_bad_key_input_is_refused(tmp_path, source, data, reason):
    with pytest.raises(UsageError) as raised:
        read_from(source, data, tmp_path)

    assert raised.value.user_message == INVALID_KEY
    assert raised.value.detail == f"key input: {reason}"
    assert raised.value.exit_code is ExitCode.USAGE


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize(
    "data",
    [
        b"a",
        b"a" * KEY_CAP_CLI,
        b"a" * KEY_CAP_CLI + b"\n",
        b"a" * KEY_CAP_CLI + b"\r\n",
    ],
)
def test_key_input_boundaries_accepted(tmp_path, source, data):
    wrapped = read_from(source, data, tmp_path)

    assert len(wrapped) == len(strip_one_line_ending(data))
    wrapped.clear()


@pytest.mark.parametrize(
    ("typed", "reason"),
    [
        ("", "empty"),
        ("a\x00b", "contains a NUL byte"),
        ("a" * (KEY_CAP_CLI + 1), "longer than 1024 bytes"),
        # 513 characters, 1026 bytes: the cap counts bytes.
        ("\u00e9" * 513, "longer than 1024 bytes"),
    ],
)
def test_bad_prompt_input_is_refused(typed, reason):
    prompt, _ = prompt_returning(typed)

    with pytest.raises(UsageError) as raised:
        read_prompt(prompt)

    assert raised.value.user_message == INVALID_KEY
    assert raised.value.detail == f"key input: {reason}"


def test_refusal_messages_never_hold_the_input(tmp_path):
    data = b"secret-part\x00rest"

    with pytest.raises(UsageError) as raised:
        read_from("stdin", data, tmp_path)

    error = raised.value
    shown = f"{error}|{error.user_message}|{error.detail}".encode()
    found = b"secret-part" in shown or b"rest" in shown
    assert not found


@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_unreadable_key_file_is_a_usage_error(tmp_path, kind):
    path = tmp_path / "typed.key"
    if kind == "directory":
        path.mkdir()

    with pytest.raises(UsageError) as raised:
        read_key_input(
            source="file",
            prompt_text=PROMPT,
            file_path=str(path),
            stdin=io.BytesIO(b""),
            tty_prompt=refuse_prompt,
        )

    assert raised.value.user_message == UNREADABLE_FILE
    assert raised.value.detail.startswith(f"{path}: ")


def test_file_source_needs_a_path():
    with pytest.raises(ValueError, match="file_path"):
        read_key_input(
            source="file",
            prompt_text=PROMPT,
            file_path=None,
            stdin=io.BytesIO(b""),
            tty_prompt=refuse_prompt,
        )


def test_unknown_source_is_a_programming_error():
    with pytest.raises(ValueError, match="key source"):
        read_key_input(
            source="argv",
            prompt_text=PROMPT,
            file_path=None,
            stdin=io.BytesIO(b""),
            tty_prompt=refuse_prompt,
        )


def test_stdin_is_read_in_pieces_until_end(tmp_path):
    class Trickle(io.RawIOBase):
        """Returns at most three bytes per read, like a slow pipe."""

        def __init__(self, data: bytes) -> None:
            self._data = data

        def readable(self) -> bool:
            return True

        def read(self, size: int = -1) -> bytes:
            piece, self._data = self._data[:3], self._data[3:]
            return piece

    wrapped = read_key_input(
        source="stdin",
        prompt_text=PROMPT,
        file_path=None,
        stdin=Trickle(KEY + b"\n"),
        tty_prompt=refuse_prompt,
    )

    assert holds(wrapped, KEY)


def test_stdin_that_fails_mid_read_is_a_usage_error():
    class Broken(io.RawIOBase):
        """Gives part of a key, then fails like a pipe that broke."""

        def __init__(self) -> None:
            self._calls = 0

        def readable(self) -> bool:
            return True

        def read(self, size: int = -1) -> bytes:
            self._calls += 1
            if self._calls == 1:
                return b"partial-"
            raise OSError(5, "Input/output error")

    with pytest.raises(UsageError) as raised:
        read_key_input(
            source="stdin",
            prompt_text=PROMPT,
            file_path=None,
            stdin=Broken(),
            tty_prompt=refuse_prompt,
        )

    assert raised.value.user_message == UNREADABLE_STDIN
    assert raised.value.detail == "stdin: Input/output error"


# --- status: the permission check before use (DD-18) ------------------------------


def test_status_ok(ctx, keys_dir):
    write_key(keys_dir)

    assert status(ctx, UUID) is KeyStatus.OK


@pytest.mark.parametrize("size", [1, KEY_CAP_CLI])
def test_status_size_boundaries_ok(ctx, keys_dir, size):
    write_key(keys_dir, b"k" * size)

    assert status(ctx, UUID) is KeyStatus.OK


def test_status_owner_only_modes_are_ok(ctx, keys_dir):
    write_key(keys_dir, mode=0o400)

    assert status(ctx, UUID) is KeyStatus.OK


def test_status_missing_file(ctx, keys_dir):
    assert status(ctx, UUID) is KeyStatus.MISSING


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o601])
def test_status_file_with_group_or_other_bits_is_bad(ctx, keys_dir, mode, caplog):
    write_key(keys_dir, mode=mode)

    with caplog.at_level("WARNING", logger="steamos_mounter.keystore"):
        result = status(ctx, UUID)

    assert result is KeyStatus.BAD_PERMISSIONS
    assert caplog.messages == [
        f"key file not trusted: /{KEYS}/{UUID}.key: mode {mode:#o} has forbidden "
        f"bits {mode & 0o077:#o}"
    ]


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o701, 0o710])
def test_status_directory_with_group_or_other_bits_is_bad(ctx, keys_dir, mode):
    write_key(keys_dir)
    keys_dir.chmod(mode)

    assert status(ctx, UUID) is KeyStatus.BAD_PERMISSIONS


@pytest.mark.parametrize("size", [0, KEY_CAP_CLI + 1])
def test_status_size_outside_1_to_1024_is_bad(ctx, keys_dir, size, caplog):
    write_key(keys_dir, b"k" * size)

    with caplog.at_level("WARNING", logger="steamos_mounter.keystore"):
        result = status(ctx, UUID)

    assert result is KeyStatus.BAD_PERMISSIONS
    assert caplog.messages == [
        f"key file not trusted: /{KEYS}/{UUID}.key: size {size} is not 1 to 1024"
    ]


def test_status_symlinked_key_file_is_bad(ctx, keys_dir, tmp_path):
    real = tmp_path / "elsewhere.key"
    real.write_bytes(KEY)
    real.chmod(0o600)
    (keys_dir / f"{UUID}.key").symlink_to(real)

    assert status(ctx, UUID) is KeyStatus.BAD_PERMISSIONS


def test_status_dangling_symlink_is_bad_not_missing(ctx, keys_dir, tmp_path):
    (keys_dir / f"{UUID}.key").symlink_to(tmp_path / "nowhere.key")

    assert status(ctx, UUID) is KeyStatus.BAD_PERMISSIONS


def test_status_key_path_that_is_a_directory_is_bad(ctx, keys_dir):
    (keys_dir / f"{UUID}.key").mkdir(mode=0o700)

    assert status(ctx, UUID) is KeyStatus.BAD_PERMISSIONS


def test_status_symlinked_directory_is_bad(ctx, tmp_path):
    real = tmp_path / "real-keys"
    real.mkdir(mode=0o700)
    write_key(real)
    link = tmp_path / KEYS
    link.parent.mkdir(parents=True)
    link.symlink_to(real)

    assert status(ctx, UUID) is KeyStatus.BAD_PERMISSIONS


def test_status_missing_directory_is_bad(ctx):
    assert status(ctx, UUID) is KeyStatus.BAD_PERMISSIONS


def test_status_wrong_owner_is_bad(ctx, keys_dir):
    write_key(keys_dir)
    other = dataclasses.replace(
        ctx, platform=dataclasses.replace(ctx.platform, trusted_uid=os.getuid() + 1)
    )

    assert status(other, UUID) is KeyStatus.BAD_PERMISSIONS


# --- store and delete (AC-011) ----------------------------------------------------


def test_store_modes(ctx, keys_dir, secret):
    store(ctx, UUID, secret)

    path = keys_dir / f"{UUID}.key"
    info = os.lstat(path)
    stored = path.read_bytes() == KEY
    assert stat.S_ISREG(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == ctx.platform.trusted_uid
    assert stat.S_IMODE(os.lstat(keys_dir).st_mode) == 0o700
    assert stored
    assert sorted(item.name for item in keys_dir.iterdir()) == [f"{UUID}.key"]
    assert status(ctx, UUID) is KeyStatus.OK


def test_store_replaces_an_old_key(ctx, keys_dir, secret):
    write_key(keys_dir, b"old-key", mode=0o644)

    store(ctx, UUID, secret)

    path = keys_dir / f"{UUID}.key"
    replaced = path.read_bytes() == KEY
    assert replaced
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600


def test_store_leaves_the_secret_to_its_owner(ctx, keys_dir, secret):
    store(ctx, UUID, secret)

    still_live = secret.reveal() == KEY
    assert still_live


@pytest.mark.parametrize("problem", ["mode", "missing", "symlink"])
def test_store_refuses_an_untrusted_directory(ctx, tmp_path, secret, problem):
    keys = tmp_path / KEYS
    if problem == "mode":
        keys.mkdir(parents=True, mode=0o755)
        keys.chmod(0o755)
    elif problem == "symlink":
        real = tmp_path / "real-keys"
        real.mkdir(mode=0o700)
        keys.parent.mkdir(parents=True)
        keys.symlink_to(real)

    with pytest.raises(MounterError) as raised:
        store(ctx, UUID, secret)

    assert raised.value.user_message == (
        "the key store cannot be trusted. "
        "Run sudo /opt/steamos-mounter/bin/steamos-mounter doctor"
    )
    assert raised.value.detail.startswith(f"/{KEYS}: ")
    assert raised.value.exit_code is ExitCode.FAILED
    assert not list(tmp_path.rglob("*.key"))


@pytest.mark.parametrize("size", [0, KEY_CAP_CLI + 1])
def test_store_refuses_a_key_outside_1_to_1024_bytes(ctx, keys_dir, size):
    with SecretBytes(b"k" * size) as wrapped, pytest.raises(ValueError, match="1 to"):
        store(ctx, UUID, wrapped)

    assert list(keys_dir.iterdir()) == []


def test_store_refuses_a_non_uuid(ctx, keys_dir, secret):
    with pytest.raises(ValueError, match="not a registry UUID"):
        store(ctx, "../escape", secret)

    assert list(keys_dir.iterdir()) == []


def test_delete_removes_the_key_file(ctx, keys_dir):
    path = write_key(keys_dir)

    assert delete(ctx, UUID) is True
    assert not path.exists()


def test_delete_without_a_key_is_false(ctx, keys_dir):
    assert delete(ctx, UUID) is False


def test_delete_without_the_directory_is_false(ctx):
    assert delete(ctx, UUID) is False


def test_module_paths_are_the_design_paths():
    assert keystore.KEYS_DIR == "/var/lib/steamos-mounter/keys"
    assert keystore.KEY_MODE == 0o600
