"""Runtime tree and runtime records.

Design Doc "Runtime State Records" (D002, Record Schema (Format 1), Write
Rules), DD-10 and the Required Specific Test "Runtime tree at boot". The tree
and the records are real files under ``HostPaths(root=tmp_path)``;
``trusted_uid`` is the test uid, so the owner checks run for real.
"""

import dataclasses
import json
import os
import stat
from pathlib import Path

import pytest

from steamos_mounter import records
from steamos_mounter.errors import ExitCode, MounterError
from steamos_mounter.locks import volume_lock
from steamos_mounter.model import InstanceKind, Trigger, VolumeState
from steamos_mounter.records import (
    RECORD_FORMAT,
    RUNTIME_DIRS,
    Record,
    delete_record,
    ensure_runtime_dirs,
    load_record,
    record_path,
    update_record,
)
from tests.helpers.builders import RECORD_EXAMPLE, record_dict

RUN = "run"
TREE_ROOT = "run/steamos-mounter"
MANIFEST_RUN_ROWS = (
    ("/run/steamos-mounter", 0o755),
    ("/run/steamos-mounter/records", 0o755),
    ("/run/steamos-mounter/records/registered", 0o755),
    ("/run/steamos-mounter/records/auto", 0o755),
    ("/run/steamos-mounter/locks", 0o700),
)
MEDIABOX_KEY = "01d95f1575592a30"
PERSONAL_KEY = "658207d5-5177-4a52-a297-31643c64724d"
PERSONAL_PATH = "/run/media/deck/PERSONAL"
SHORT = 0.1


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _write_record(ctx, kind: InstanceKind, key: str, data: dict) -> Path:
    path = record_path(ctx, kind, key)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _registered(key: str, **changes) -> dict:
    return record_dict(kind="registered", key=key, **changes)


def _auto(key: str, **changes) -> dict:
    return record_dict(kind="auto", key=key, mapping=None, **changes)


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """``/run`` as it is after boot: present, without our tree."""
    directory = tmp_path / RUN
    directory.mkdir()
    return directory


@pytest.fixture
def runtime(ctx, run_dir) -> Path:
    """The tree a root entry has created."""
    ensure_runtime_dirs(ctx)
    return run_dir / "steamos-mounter"


def _foreign_owner(ctx):
    platform = dataclasses.replace(ctx.platform, trusted_uid=os.getuid() + 1)
    return dataclasses.replace(ctx, platform=platform)


# --- runtime tree at boot (D002) ------------------------------------------------------


def test_runtime_dirs_equal_the_manifest_run_rows():
    assert RUNTIME_DIRS == MANIFEST_RUN_ROWS


def test_fresh_root_has_no_tree_and_no_lock_can_be_taken(ctx, run_dir):
    assert not (run_dir / "steamos-mounter").exists()

    with pytest.raises(MounterError), volume_lock(ctx, MEDIABOX_KEY, timeout=SHORT):
        pass


def test_first_root_entry_creates_all_five_directories_before_the_first_lock(
    ctx, run_dir, tmp_path
):
    ensure_runtime_dirs(ctx)

    for absolute, mode in MANIFEST_RUN_ROWS:
        path = tmp_path / absolute.lstrip("/")
        assert path.is_dir()
        assert _mode(path) == mode
    with volume_lock(ctx, MEDIABOX_KEY, timeout=SHORT):
        assert (
            tmp_path / TREE_ROOT / "locks" / f"volume-{MEDIABOX_KEY}.lock"
        ).is_file()


def test_modes_do_not_depend_on_the_callers_umask(ctx, run_dir, tmp_path):
    previous = os.umask(0o077)
    try:
        ensure_runtime_dirs(ctx)
    finally:
        os.umask(previous)

    assert _mode(tmp_path / TREE_ROOT / "records") == 0o755


def test_existing_directories_get_the_manifest_modes(ctx, run_dir, tmp_path):
    locks_dir = tmp_path / TREE_ROOT / "locks"
    locks_dir.mkdir(parents=True)
    locks_dir.chmod(0o777)

    ensure_runtime_dirs(ctx)

    assert _mode(locks_dir) == 0o700
    assert _mode(tmp_path / TREE_ROOT) == 0o755


def test_second_root_entry_changes_nothing(ctx, runtime):
    record = runtime / "records" / "auto" / "keep.json"
    record.write_text("{}", encoding="utf-8")

    ensure_runtime_dirs(ctx)

    assert record.read_text(encoding="utf-8") == "{}"


def test_symlinked_tree_root_fails_closed_with_no_device_action(
    ctx, run_dir, tmp_path, fake_runner
):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    elsewhere.chmod(0o750)
    (run_dir / "steamos-mounter").symlink_to(elsewhere)

    with pytest.raises(MounterError) as caught:
        ensure_runtime_dirs(ctx)

    assert caught.value.exit_code is ExitCode.FAILED
    assert "symlink" in caught.value.detail
    assert _mode(elsewhere) == 0o750
    assert os.listdir(elsewhere) == []
    assert fake_runner.calls == []


def test_symlink_inside_the_tree_fails_before_the_later_directories(
    ctx, run_dir, tmp_path
):
    records = tmp_path / TREE_ROOT / "records"
    records.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (records / "registered").symlink_to(elsewhere)

    with pytest.raises(MounterError):
        ensure_runtime_dirs(ctx)

    assert not (records / "auto").exists()
    assert not (tmp_path / TREE_ROOT / "locks").exists()


def test_foreign_owner_fails_closed_with_no_device_action(ctx, runtime, fake_runner):
    with pytest.raises(MounterError) as caught:
        ensure_runtime_dirs(_foreign_owner(ctx))

    assert "owned by uid" in caught.value.detail
    assert "doctor" in caught.value.user_message
    assert fake_runner.calls == []


def test_a_file_in_place_of_a_directory_fails_closed(ctx, run_dir, tmp_path):
    (tmp_path / TREE_ROOT).mkdir()
    (tmp_path / TREE_ROOT / "records").write_text("", encoding="utf-8")

    with pytest.raises(MounterError) as caught:
        ensure_runtime_dirs(ctx)

    assert "not a directory" in caught.value.detail


def test_mode_that_cannot_be_set_fails_closed(ctx, run_dir, monkeypatch):
    def refuse(fd, mode):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(records.os, "fchmod", refuse)

    with pytest.raises(MounterError) as caught:
        ensure_runtime_dirs(ctx)

    assert "mode not set" in caught.value.detail


def test_missing_run_fails_closed(ctx):
    with pytest.raises(MounterError) as caught:
        ensure_runtime_dirs(ctx)

    assert "/run/steamos-mounter" in caught.value.detail


def test_non_root_entry_creates_nothing(ctx_deck, run_dir):
    ensure_runtime_dirs(ctx_deck)

    assert os.listdir(run_dir) == []


# --- record paths ---------------------------------------------------------------------


def test_registered_record_path_uses_the_lowercased_uuid(ctx, tmp_path):
    path = record_path(ctx, InstanceKind.REGISTERED, "01D95F1575592A30")

    assert path == tmp_path / TREE_ROOT / "records/registered/01d95f1575592a30.json"


def test_auto_record_path_uses_the_device_key(ctx, tmp_path):
    path = record_path(ctx, InstanceKind.AUTO, "dm-0-252_0")

    assert path == tmp_path / TREE_ROOT / "records/auto/dm-0-252_0.json"


@pytest.mark.parametrize("key", ["", "../etc", "a/b", ".hidden", "x" * 129, "sdb1 2"])
def test_record_path_refuses_a_key_that_is_not_a_file_name(ctx, key):
    with pytest.raises(ValueError):
        record_path(ctx, InstanceKind.AUTO, key)


# --- loading records ------------------------------------------------------------------


def test_missing_record_is_none(ctx, runtime):
    assert load_record(ctx, InstanceKind.REGISTERED, MEDIABOX_KEY) is None


def test_missing_tree_is_no_record(ctx_deck, run_dir):
    assert load_record(ctx_deck, InstanceKind.AUTO, "sdc1-8_33") is None


def test_record_schema_example_round_trip(ctx, runtime):
    _write_record(ctx, InstanceKind.REGISTERED, PERSONAL_KEY, RECORD_EXAMPLE)

    record = load_record(ctx, InstanceKind.REGISTERED, PERSONAL_KEY)

    assert isinstance(record, Record)
    assert record.to_dict() == RECORD_EXAMPLE
    assert record.kind is InstanceKind.REGISTERED
    assert record.state is VolumeState.MOUNTED_RW_DIRTY
    assert record.trigger is Trigger.START
    assert record.mount["status"] == "mounted"


def test_record_from_dict_and_to_dict_are_inverse():
    assert Record.from_dict(RECORD_EXAMPLE).to_dict() == RECORD_EXAMPLE


def test_record_format_is_one():
    assert RECORD_FORMAT == 1


def _replace(**changes) -> dict:
    return record_dict(**changes)


def _without(field: str) -> dict:
    data = record_dict()
    del data[field]
    return data


def _with_extra() -> dict:
    data = record_dict()
    data["key_material"] = "x"
    return data


UNREADABLE = {
    "format-2": _replace(format=2),
    "format-text": _replace(format="1"),
    "format-true": _replace(format=True),
    "missing-field": _without("busy"),
    "unknown-field": _with_extra(),
    "unknown-state": _replace(state="Mounted"),
    "unknown-kind": _replace(kind="manual"),
    "unknown-trigger": _replace(trigger="boot"),
    "name-not-text": _replace(name=7),
    "reason-not-text": _replace(reason=["dirty"]),
    "mount-not-object": _replace(mount="mounted"),
    "attempt-null": _replace(attempt=None),
    "busy-not-list": _replace(busy="target"),
    "busy-item-not-text": _replace(busy=[1]),
    "kind-differs-from-path": _replace(kind="auto"),
    "key-differs-from-path": _replace(key="01d95f1575592a30"),
}


@pytest.mark.parametrize("data", UNREADABLE.values(), ids=UNREADABLE.keys())
def test_record_that_breaks_the_schema_is_unreadable(ctx, runtime, data):
    _write_record(ctx, InstanceKind.REGISTERED, PERSONAL_KEY, data)

    assert load_record(ctx, InstanceKind.REGISTERED, PERSONAL_KEY) == "unreadable"


@pytest.mark.parametrize(
    "raw",
    [b"{not json", b"[1, 2]", b"\xff\xfe", b""],
    ids=["bad-json", "not-object", "not-utf8", "empty"],
)
def test_record_that_is_not_a_json_object_is_unreadable(ctx, runtime, raw):
    record_path(ctx, InstanceKind.AUTO, "sdc1-8_33").write_bytes(raw)

    assert load_record(ctx, InstanceKind.AUTO, "sdc1-8_33") == "unreadable"


def test_symlinked_record_is_unreadable_and_not_followed(ctx, runtime, tmp_path):
    target = tmp_path / "planted.json"
    target.write_text(json.dumps(_registered(MEDIABOX_KEY)), encoding="utf-8")
    record_path(ctx, InstanceKind.REGISTERED, MEDIABOX_KEY).symlink_to(target)

    assert load_record(ctx, InstanceKind.REGISTERED, MEDIABOX_KEY) == "unreadable"


def test_fifo_in_place_of_a_record_is_unreadable_without_hanging(ctx, runtime):
    os.mkfifo(record_path(ctx, InstanceKind.REGISTERED, MEDIABOX_KEY))

    assert load_record(ctx, InstanceKind.REGISTERED, MEDIABOX_KEY) == "unreadable"


def test_directory_in_place_of_a_record_is_unreadable(ctx, runtime):
    record_path(ctx, InstanceKind.REGISTERED, MEDIABOX_KEY).mkdir()

    assert load_record(ctx, InstanceKind.REGISTERED, MEDIABOX_KEY) == "unreadable"


# --- writing records (DD-10, Write Rules) ---------------------------------------------


def _write_ahead_mount(record: Record) -> None:
    record.name = "PERSONAL"
    record.state = VolumeState.MOUNTING
    record.mount = {
        "status": "pending",
        "target": PERSONAL_PATH,
        "device": None,
        "devnum": None,
        "driver": None,
        "mode": None,
        "created_dir": False,
    }


def _write_ahead_mapping(record: Record) -> None:
    record.mapping = {
        "name": f"steamos-mounter-{PERSONAL_KEY}",
        "kname": None,
        "devnum": None,
        "opened_by": "handler",
        "key_unit_invocation_id": None,
        "save_pending": False,
    }


def test_write_ahead_fields_reach_the_file_before_the_action(ctx, runtime):
    with volume_lock(ctx, PERSONAL_KEY, timeout=SHORT):
        update_record(ctx, InstanceKind.REGISTERED, PERSONAL_KEY, _write_ahead_mount)
        update_record(ctx, InstanceKind.REGISTERED, PERSONAL_KEY, _write_ahead_mapping)

    path = record_path(ctx, InstanceKind.REGISTERED, PERSONAL_KEY)
    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["mount"]["status"] == "pending"
    assert written["mount"]["target"] == PERSONAL_PATH
    assert written["mapping"]["name"] == f"steamos-mounter-{PERSONAL_KEY}"
    assert written["state"] == "Mounting"
    assert _mode(path) == 0o644


def test_new_record_has_the_schema_shape_and_identity(ctx, runtime):
    record = update_record(ctx, InstanceKind.AUTO, "sdc1-8_33", lambda r: None)

    written = json.loads(
        record_path(ctx, InstanceKind.AUTO, "sdc1-8_33").read_text(encoding="utf-8")
    )
    assert set(written) == set(RECORD_EXAMPLE)
    assert written["format"] == 1
    assert written["kind"] == "auto"
    assert written["key"] == "sdc1-8_33"
    assert written["invocation_id"] == "0f6c9c1e5c7a4c51a0a5f3f3b2b6d7e8"
    assert written["updated_at"] == "2026-10-08T02:11:40Z"
    assert written["state"] == "NotMounted"
    assert written["mount"] is None
    assert written["attempt"] == {"probe": None, "steps": [], "skipped": []}
    assert written["dialog"] == {"outcome": None, "at": None}
    assert written["busy"] == []
    assert record.to_dict() == written


def test_update_keeps_the_schema_example_byte_for_byte_in_content(ctx, runtime):
    path = _write_record(ctx, InstanceKind.REGISTERED, PERSONAL_KEY, RECORD_EXAMPLE)

    update_record(ctx, InstanceKind.REGISTERED, PERSONAL_KEY, lambda r: None)

    assert json.loads(path.read_text(encoding="utf-8")) == RECORD_EXAMPLE


def test_update_stamps_the_time_of_the_write(ctx, runtime, fake_clock):
    fake_clock.advance(65)

    record = update_record(ctx, InstanceKind.AUTO, "sdc1-8_33", lambda r: None)

    assert record.updated_at == "2026-10-08T02:12:45Z"


def test_update_lowercases_a_registered_key(ctx, runtime):
    update_record(ctx, InstanceKind.REGISTERED, "01D95F1575592A30", lambda r: None)

    record = load_record(ctx, InstanceKind.REGISTERED, MEDIABOX_KEY)
    assert isinstance(record, Record)
    assert record.key == MEDIABOX_KEY


def test_update_writes_ascii_and_keeps_unicode_names(ctx, runtime):
    def name_it(record: Record) -> None:
        record.name = "MÉDIA"

    update_record(ctx, InstanceKind.AUTO, "sdc1-8_33", name_it)

    raw = record_path(ctx, InstanceKind.AUTO, "sdc1-8_33").read_bytes()
    assert raw.isascii()
    record = load_record(ctx, InstanceKind.AUTO, "sdc1-8_33")
    assert isinstance(record, Record)
    assert record.name == "MÉDIA"


def test_update_replaces_an_unreadable_record_with_a_fresh_one(ctx, runtime, caplog):
    path = record_path(ctx, InstanceKind.AUTO, "sdc1-8_33")
    path.write_bytes(b"{broken")

    record = update_record(ctx, InstanceKind.AUTO, "sdc1-8_33", lambda r: None)

    assert record.state is VolumeState.NOT_MOUNTED
    assert json.loads(path.read_text(encoding="utf-8"))["key"] == "sdc1-8_33"
    assert any("unreadable" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("field", ["kind", "key", "format"])
def test_update_refuses_a_change_of_identity(ctx, runtime, field):
    path = _write_record(ctx, InstanceKind.REGISTERED, PERSONAL_KEY, RECORD_EXAMPLE)
    values = {"kind": InstanceKind.AUTO, "key": MEDIABOX_KEY, "format": 2}

    def rename(record: Record) -> None:
        setattr(record, field, values[field])

    with pytest.raises(ValueError):
        update_record(ctx, InstanceKind.REGISTERED, PERSONAL_KEY, rename)

    assert json.loads(path.read_text(encoding="utf-8")) == RECORD_EXAMPLE


def test_update_without_the_tree_fails(ctx, run_dir):
    with pytest.raises(OSError):
        update_record(ctx, InstanceKind.AUTO, "sdc1-8_33", lambda r: None)


def test_delete_record_removes_the_file(ctx, runtime):
    path = _write_record(ctx, InstanceKind.AUTO, "sdc1-8_33", _auto("sdc1-8_33"))

    delete_record(ctx, InstanceKind.AUTO, "sdc1-8_33")

    assert not path.exists()


def test_delete_of_a_missing_record_is_fine(ctx, runtime):
    delete_record(ctx, InstanceKind.AUTO, "sdc1-8_33")

    assert load_record(ctx, InstanceKind.AUTO, "sdc1-8_33") is None
