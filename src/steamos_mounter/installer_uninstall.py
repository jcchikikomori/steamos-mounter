"""``uninstall``: unwire first, then stop, then remove; ``/opt`` last.

Design Doc "Python uninstall (Unwire First, Then Stop)" and the "Install,
Update and Uninstall" diagram; ADR-0004 D7 and D8. Split out of
``installer`` by step; ``installer`` re-exports ``uninstall``.

1. Guards; no ``/opt/steamos-mounter`` -> "nothing to remove", exit 0.
2. Every module this needs is imported at load time, before anything is
   removed, and the installed manifest (``current/data/manifest.tsv``) is
   read first: the release tree goes last.
3. The udev rule, then ``udevadm control --reload``: no new auto instances.
4. Every ``.device.wants`` link, then ``daemon-reload``: no registered ones.
5. Key units, then every other instance, stopped blocking (120 s); each
   record's ``busy`` list is read once they are down.
6. The other manifest ``file`` rows (units, drop-in), then ``daemon-reload``.
7. The registry moves to ``kept-config.toml`` (the keys stay), or with
   ``--purge`` the registry, the keys and ``/var/lib/steamos-mounter`` go.
8. ``/run/steamos-mounter``, ``/etc/steamos-mounter`` when empty, then
   ``/opt/steamos-mounter``.
9. One busy line per busy item (exit 6); a failed step gives exit 5.

A failure while unwiring or stopping ends the run there: an instance that is
still wired is never stopped, and nothing is removed under a running one
(ADR-0004 D8). After a later failure ``/opt`` stays, so running uninstall
again from the installed copy finishes the job.
"""

import contextlib
import errno
import os
from pathlib import Path
from typing import TYPE_CHECKING, Final

from steamos_mounter import config, locks, records, systemd, wiring
from steamos_mounter.atomicfile import write_atomic
from steamos_mounter.errors import ToolError
from steamos_mounter.installer_report import (
    CURRENT_LINK,
    KEPT_REGISTRY,
    OPT_DIR,
    RUNTIME_DIR,
    STATE_DIR,
    UNINSTALL,
    Done,
    InstallReport,
    Steps,
    dir_mode,
    ensure_dir,
    file_rows,
    fixed_umask,
    ok,
    read_manifest,
    refuse_guards,
    remove_path,
    skipped,
    udevadm_reload,
)
from steamos_mounter.manifest import Entry
from steamos_mounter.model import InstanceKind, Registry
from steamos_mounter.records import Record
from steamos_mounter.routing import AUTO_TEMPLATE, REGISTERED_TEMPLATE

if TYPE_CHECKING:
    from steamos_mounter.context import Context

NOTHING_TO_REMOVE: Final = "nothing to remove"
UDEV_RULE_ROLE: Final = "udev-rule"
KEY_TEMPLATE: Final = "steamos-mounter-key@"
STILL_BUSY: Final = "still busy: finishes when the last open file is closed"
OPT_KEPT: Final = "an earlier step failed: run uninstall again"
EMPTY_REGISTRY: Final = Registry(
    schema_version=config.SCHEMA_VERSION, volumes=(), invalid=()
)
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


def uninstall(ctx: "Context", *, purge: bool) -> InstallReport:
    """Remove every installed file; keep the registry and keys unless ``purge``."""
    with fixed_umask():
        return _uninstall(ctx, purge=purge)


def _uninstall(ctx: "Context", *, purge: bool) -> InstallReport:
    refused = refuse_guards(ctx)
    if refused is not None:
        return refused
    steps = Steps(UNINSTALL)
    if not os.path.lexists(ctx.paths.p(OPT_DIR)):
        steps.add("check", "skipped", NOTHING_TO_REMOVE)
        return steps.report()
    entries = steps.attempt("manifest", lambda: _installed(ctx))
    if entries is None or not _unwire_and_stop(ctx, steps, entries):
        return steps.report()
    busy = _busy(ctx)
    for entry in file_rows(entries):
        if entry.role != UDEV_RULE_ROLE:
            steps.run(f"remove {entry.path}", lambda entry=entry: _unlink(ctx, entry))
    steps.run("daemon-reload", lambda: _daemon_reload(ctx))
    steps.run("registry", lambda: _registry(ctx, entries, purge=purge))
    steps.run(f"remove {RUNTIME_DIR}", lambda: _remove_tree(ctx, RUNTIME_DIR))
    steps.run(f"remove {config.REGISTRY_DIR}", lambda: _remove_empty(ctx))
    if steps.failed:
        steps.add(f"remove {OPT_DIR}", "skipped", OPT_KEPT)
    else:
        steps.run(f"remove {OPT_DIR}", lambda: _remove_tree(ctx, OPT_DIR))
    for name, item in busy:
        steps.add(name, "busy", f"{item} {STILL_BUSY}")
    return steps.report()


def _installed(ctx: "Context") -> tuple[Done, tuple[Entry, ...]]:
    entries = read_manifest(ctx.paths.p(CURRENT_LINK))
    return ok(), entries


def _unwire_and_stop(ctx: "Context", steps: Steps, entries: tuple[Entry, ...]) -> bool:
    """Steps 3 to 5; False at the first failure (nothing is stopped while wired)."""
    rules = [entry for entry in file_rows(entries) if entry.role == UDEV_RULE_ROLE]
    return (
        all(
            steps.run(f"remove {rule.path}", lambda r=rule: _unlink(ctx, r))
            for rule in rules
        )
        and steps.run("udevadm reload", lambda: udevadm_reload(ctx))
        and steps.run("unwire", lambda: _unwire(ctx))
        and steps.run("daemon-reload", lambda: _daemon_reload(ctx))
        and steps.run("stop key units", lambda: _stop(ctx, (f"{KEY_TEMPLATE}*",)))
        and steps.run(
            "stop instances",
            lambda: _stop(ctx, (f"{REGISTERED_TEMPLATE}*", f"{AUTO_TEMPLATE}*")),
        )
    )


def _unlink(ctx: "Context", entry: Entry) -> Done:
    try:
        os.unlink(ctx.paths.p(entry.path))
    except FileNotFoundError:
        return skipped()
    return ok()


def _unwire(ctx: "Context") -> Done:
    change = wiring.sync_links(ctx, EMPTY_REGISTRY)
    return ok(f"{len(change.removed)} removed") if change.removed else skipped()


def _daemon_reload(ctx: "Context") -> Done:
    systemd.daemon_reload(ctx)
    return ok()


def _stop(ctx: "Context", patterns: tuple[str, ...]) -> Done:
    """Stop every loaded unit matching ``patterns``, blocking (teardown runs)."""
    units = systemd.list_units(ctx, patterns)
    if not units:
        return skipped()
    result = systemd.stop(ctx, units, block=True)
    if result.returncode != 0:
        raise ToolError(
            "the instances did not stop: run uninstall again",
            detail=(
                f"systemctl stop {' '.join(units)}: exit {result.returncode}, timed "
                f"out {result.timed_out}: {result.err_text().strip()}"
            ),
        )
    return ok(", ".join(units))


def _busy(ctx: "Context") -> list[tuple[str, str]]:
    """``(name, item)`` for every item a teardown left busy, by record."""
    found: list[tuple[str, str]] = []
    for kind in InstanceKind:
        directory = ctx.paths.p(f"{records.RECORDS_DIR}/{kind.value}")
        try:
            names = sorted(os.listdir(directory))
        except FileNotFoundError:
            continue
        for name in names:
            record = _record(ctx, kind, name)
            if record is not None:
                found.extend((record.name or record.key, item) for item in record.busy)
    return found


def _record(ctx: "Context", kind: InstanceKind, name: str) -> Record | None:
    key = name.removesuffix(records.RECORD_SUFFIX)
    if key == name:
        return None
    try:
        record = records.load_record(ctx, kind, key)
    except ValueError:  # not a record key: not a file this tool wrote
        return None
    return record if isinstance(record, Record) else None


def _registry(ctx: "Context", entries: tuple[Entry, ...], *, purge: bool) -> Done:
    etc = ctx.paths.p(config.REGISTRY_PATH)
    if purge:
        _unlink_quietly(etc)
        _remove_tree(ctx, STATE_DIR)
        return ok("registry and keys deleted")
    if not os.path.lexists(etc):
        return skipped("no registry")
    with locks.registry_lock(ctx):
        data = _read(etc)
        ensure_dir(ctx, STATE_DIR, dir_mode(entries, STATE_DIR))
        uid = ctx.platform.trusted_uid
        mode = config.REGISTRY_MODE
        write_atomic(
            ctx.paths.p(KEPT_REGISTRY), data, mode=mode, uid=uid, gid=os.getegid()
        )
        os.unlink(etc)
    return ok(f"kept at {KEPT_REGISTRY}; keys kept")


def _read(path: Path) -> bytes:
    with os.fdopen(os.open(path, _FILE_FLAGS), "rb") as stream:
        return stream.read()


def _unlink_quietly(path: Path) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


def _remove_tree(ctx: "Context", absolute: str) -> Done:
    return ok() if remove_path(ctx.paths.p(absolute)) else skipped()


def _remove_empty(ctx: "Context") -> Done:
    """``/etc/steamos-mounter`` only when nothing is left in it."""
    try:
        os.rmdir(ctx.paths.p(config.REGISTRY_DIR))
    except FileNotFoundError:
        return skipped()
    except OSError as error:
        if error.errno != errno.ENOTEMPTY:
            raise
        return skipped("not empty: left in place")
    return ok()
