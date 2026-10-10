"""``install`` (install equals update) and ``uninstall``: the step bodies.

Design Doc "Installer, Updater and Uninstaller" (Python ``install`` steps 1
to 12, Python ``uninstall``), "Install Manifest (Authoritative)", DD-24 and
the "Install, Update and Uninstall" diagram; ADR-0004 D1, D7, D8.6 and D11.
``install.sh`` stages a root-owned release under
``/opt/steamos-mounter/releases/`` and execs that copy's entry point, which
runs ``install`` here; ``uninstall`` lives in ``installer_uninstall`` and the
start step in ``installer_start`` (split by step, Repository Layout rule).

``install``, in order, each step one line:

1. guards (platform, root);
2. the release: ``--release`` is a direct child of ``releases/``, equals the
   running entry point's release (``ctx.release_root``, work plan decision
   item 2) and is a trusted tree (trusted owner, no group or other write, no
   symlink), as are ``/opt/steamos-mounter`` and ``releases/``; either side
   missing fails closed. Without ``--release`` the active release (what
   ``current`` names) is repaired: steps 4 to 12 again, no compile;
3. ``compileall`` of the release's ``lib``;
4. the manifest's directories with owner and mode (``/run`` rows through
   ``records.ensure_runtime_dirs``, D002);
5. the flip: ``current -> releases/<name>`` in one rename, ``bin -> current/bin``;
6. each manifest ``file`` row, written only when content, owner or mode differ;
7. the kept registry moved back to ``/etc`` (ADR-0004 D8.6);
8. the wiring from the registry, or "registry unusable: wiring unchanged";
9. ``daemon-reload`` and ``udevadm control --reload``;
10. starts of inactive instances of present devices, unless ``--no-start``;
11. ``ensure_mount_base``;
12. prune: keep ``current`` and the release installed just before it.

A failure in steps 2, 3 or 5 stops the run: nothing that follows is safe
without a trusted, compiled, active release. Any other failed step lets the
rest run and makes the exit code 5. Active instances are never stopped or
restarted (ADR-0001, ADR-0004 D7).
"""

import compileall
import contextlib
import io
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from steamos_mounter import config, locks, mountdirs, records, systemd, wiring
from steamos_mounter.atomicfile import check_owner_mode, replace_symlink, write_atomic
from steamos_mounter.errors import MounterError, RegistryError
from steamos_mounter.installer_report import (
    CURRENT_LINK,
    FORBIDDEN_BITS,
    INSTALL,
    KEPT_REGISTRY,
    OPT_DIR,
    RELEASE_PREFIX,
    RELEASES_DIR,
    STATE_DIR,
    Done,
    InstallReport,
    StepLine,
    Steps,
    dir_rows,
    ensure_dir,
    file_rows,
    fixed_umask,
    is_runtime,
    ok,
    read_manifest,
    refuse_guards,
    remove_path,
    row_mode,
    skipped,
    udevadm_reload,
)
from steamos_mounter.installer_start import start_present
from steamos_mounter.installer_uninstall import uninstall
from steamos_mounter.manifest import Entry
from steamos_mounter.model import Registry

if TYPE_CHECKING:
    from steamos_mounter.context import Context

__all__ = ["InstallReport", "StepLine", "install", "uninstall"]

NO_RUNNING_RELEASE: Final = "the running release is unknown: run install.sh"
NOT_A_RELEASE: Final = "--release is not a release directory under " + RELEASES_DIR
NOT_RUNNING: Final = "--release is not the release this installer runs from"
NO_ACTIVE_RELEASE: Final = "no active release to repair: run install.sh"
UNTRUSTED: Final = "the release is not a root-owned, read-only tree: run install.sh"
NOT_COMPILED: Final = "the release could not be compiled: run install.sh"
WIRING_UNCHANGED: Final = "registry unusable: wiring unchanged"
KEPT_UNUSABLE: Final = f"kept registry unusable: left in place at {KEPT_REGISTRY}"
NO_START: Final = "--no-start"
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
RELEASE_STAMP: Final = re.compile(r"-([0-9]{8}T[0-9]{6}Z)\Z")


@dataclass(frozen=True, slots=True)
class _Release:
    root: Path
    name: str
    entries: tuple[Entry, ...]


def install(
    ctx: "Context", *, release: Path | None, start_present: bool = True
) -> InstallReport:
    """Install, update or repair; never prompts, never reads stdin."""
    with fixed_umask():
        return _install(ctx, release=release, start_present=start_present)


def _install(
    ctx: "Context", *, release: Path | None, start_present: bool
) -> InstallReport:
    refused = refuse_guards(ctx)
    if refused is not None:
        return refused
    steps = Steps(INSTALL)
    chosen = steps.attempt("release", lambda: _choose(ctx, release))
    if chosen is None:
        return steps.report()
    if release is not None and not steps.run("compile", lambda: _compile(chosen)):
        return steps.report()
    steps.run("directories", lambda: _directories(ctx, chosen.entries))
    if not steps.run("current", lambda: _flip(ctx, chosen)):
        return steps.report()
    for entry in _link_rows(chosen.entries):
        steps.run(
            f"link {entry.path}",
            lambda entry=entry: _link(ctx, entry.path, entry.source),
        )
    for entry in file_rows(chosen.entries):
        steps.run(f"write {entry.path}", lambda entry=entry: _write(ctx, chosen, entry))
    steps.run("kept registry", lambda: _restore_kept(ctx))
    registry = steps.attempt("wiring", lambda: _wire(ctx))
    steps.run("daemon-reload", lambda: _daemon_reload(ctx))
    steps.run("udevadm reload", lambda: udevadm_reload(ctx))
    if not start_present:
        steps.add("start", "skipped", NO_START)
    else:
        _start(ctx, steps, registry)
    steps.run("mount base", lambda: _mount_base(ctx))
    steps.run("prune", lambda: _prune(ctx, chosen))
    return steps.report()


# --- 2. the release ---------------------------------------------------------------


def _choose(ctx: "Context", release: Path | None) -> tuple[Done, _Release]:
    if ctx.release_root is None:
        raise MounterError(NO_RUNNING_RELEASE, detail="ctx.release_root is None")
    releases = ctx.paths.p(RELEASES_DIR)
    candidate = _active(ctx) if release is None else _named(releases, release)
    if os.path.realpath(candidate) != os.path.realpath(ctx.release_root):
        raise MounterError(NOT_RUNNING, detail=f"{candidate} is not {ctx.release_root}")
    uid = ctx.platform.trusted_uid
    problem = _dir_problem(ctx.paths.p(OPT_DIR), uid) or _dir_problem(releases, uid)
    problem = problem or tree_problem(candidate, uid)
    if problem is not None:
        raise MounterError(UNTRUSTED, detail=problem)
    chosen = _Release(candidate, candidate.name, read_manifest(candidate))
    return ok(chosen.name if release is not None else f"repair {chosen.name}"), chosen


def _named(releases: Path, release: Path) -> Path:
    candidate = Path(os.path.normpath(release))
    if not candidate.is_absolute() or candidate.parent != releases:
        raise MounterError(NOT_A_RELEASE, detail=f"--release {release}")
    return candidate


def _active(ctx: "Context") -> Path:
    try:
        target = os.readlink(ctx.paths.p(CURRENT_LINK))
    except OSError as error:
        raise MounterError(NO_ACTIVE_RELEASE, detail=str(error)) from error
    name = target.removeprefix(RELEASE_PREFIX)
    if not target.startswith(RELEASE_PREFIX) or "/" in name or name in ("", "..", "."):
        raise MounterError(NO_ACTIVE_RELEASE, detail=f"current -> {target}")
    return ctx.paths.p(RELEASES_DIR) / name


def _dir_problem(path: Path, uid: int) -> str | None:
    found = check_owner_mode(path, uid=uid, forbid=FORBIDDEN_BITS, kind="dir")
    return None if found is None else f"{found.path} {found.problem}"


def _raise(error: OSError) -> None:
    raise error


def tree_problem(root: Path, uid: int) -> str | None:
    """Why the tree at ``root`` is not trusted, or None (the entry point's rule).

    Every entry, ``root`` included, is examined with ``lstat``: a symlink, an
    owner other than ``uid`` or a group or other write bit is a problem, and
    so is any entry that cannot be read (fail closed).
    """
    try:
        for dirpath, dirnames, filenames in os.walk(root, onerror=_raise):
            names = (dirpath, *(os.path.join(dirpath, n) for n in dirnames + filenames))
            problem = next(filter(None, (_entry_problem(n, uid) for n in names)), None)
            if problem is not None:
                return problem
    except OSError as error:
        return f"{root}: cannot be checked: {error.strerror}"
    return None


def _entry_problem(path: str, uid: int) -> str | None:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        return f"{path} is a symlink"
    if info.st_uid != uid:
        return f"{path} is owned by uid {info.st_uid}"
    if info.st_mode & FORBIDDEN_BITS:
        return f"{path} is writable by group or others"
    return None


# --- 3. to 6. compile, directories, flip, files -----------------------------------


def _compile(chosen: _Release) -> Done:
    """``compileall`` with ``quiet=1``; its error lines go to the journal only."""
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        compiled = compileall.compile_dir(str(chosen.root / "lib"), quiet=1)
    if not compiled:
        raise MounterError(NOT_COMPILED, detail=printed.getvalue().strip())
    return ok()


def _directories(ctx: "Context", entries: tuple[Entry, ...]) -> Done:
    changed = [
        entry.path
        for entry in dir_rows(entries)
        if not is_runtime(entry.path) and ensure_dir(ctx, entry.path, row_mode(entry))
    ]
    missing = [
        path for path, _mode in records.RUNTIME_DIRS if not ctx.paths.p(path).exists()
    ]
    records.ensure_runtime_dirs(ctx)
    created = changed + missing
    return ok(", ".join(created)) if created else skipped()


def _link_rows(entries: tuple[Entry, ...]) -> tuple[Entry, ...]:
    """``link`` rows with a fixed target (``bin``); ``current`` is the flip."""
    return tuple(e for e in entries if e.kind == "link" and e.path != CURRENT_LINK)


def _flip(ctx: "Context", chosen: _Release) -> Done:
    return _link(ctx, CURRENT_LINK, f"{RELEASE_PREFIX}{chosen.name}")


def _link(ctx: "Context", absolute: str, target: str) -> Done:
    """Point ``absolute`` at ``target`` in one rename, unless it already does."""
    path = ctx.paths.p(absolute)
    try:
        if os.readlink(path) == target:
            return skipped(target)
    except OSError:
        pass  # absent, or not a symlink: the rename replaces a file, not a dir
    replace_symlink(path, target)
    return ok(target)


def _write(ctx: "Context", chosen: _Release, entry: Entry) -> Done:
    data = (chosen.root / entry.source).read_bytes()
    path = ctx.paths.p(entry.path)
    mode, uid = row_mode(entry), ctx.platform.trusted_uid
    if _holds(path, data, mode=mode, uid=uid):
        return skipped()
    write_atomic(path, data, mode=mode, uid=uid, gid=os.getegid())
    return ok()


def _holds(path: Path, data: bytes, *, mode: int, uid: int) -> bool:
    """True when ``path`` is a regular file with ``data``, ``mode`` and ``uid``."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
        return False
    if stat.S_IMODE(info.st_mode) != mode:
        return False
    return _read(path) == data


def _read(path: Path) -> bytes:
    with os.fdopen(os.open(path, _FILE_FLAGS), "rb") as stream:
        return stream.read()


# --- 7. to 9. kept registry, wiring, reloads ---------------------------------------


def _restore_kept(ctx: "Context") -> Done:
    """Move a valid kept registry back; ``/etc`` wins when both exist (D8.6)."""
    kept = ctx.paths.p(KEPT_REGISTRY)
    if not os.path.lexists(kept):
        return skipped("no kept registry")
    etc = ctx.paths.p(config.REGISTRY_PATH)
    with locks.registry_lock(ctx):
        if os.path.lexists(etc):
            return skipped(
                f"warning: {config.REGISTRY_PATH} is in use; {KEPT_REGISTRY} left as is"
            )
        data = _kept_bytes(ctx, kept)
        uid = ctx.platform.trusted_uid
        mode = config.REGISTRY_MODE
        write_atomic(etc, data, mode=mode, uid=uid, gid=os.getegid())
        os.unlink(kept)
    return ok(f"restored {config.REGISTRY_PATH} from {KEPT_REGISTRY}")


def _kept_bytes(ctx: "Context", kept: Path) -> bytes:
    """The kept copy, after the registry's own read checks (ADR-0004 D3)."""
    uid = ctx.platform.trusted_uid
    forbid = config.FORBIDDEN_BITS
    problem = check_owner_mode(
        ctx.paths.p(STATE_DIR), uid=uid, forbid=forbid, kind="dir"
    ) or check_owner_mode(kept, uid=uid, forbid=forbid, kind="file")
    if problem is not None:
        raise MounterError(KEPT_UNUSABLE, detail=f"{problem.path}: {problem.problem}")
    data = _read(kept)
    try:
        config.parse(data.decode("utf-8"), mount_base=ctx.platform.mount_base)
    except (UnicodeDecodeError, RegistryError) as error:
        raise MounterError(KEPT_UNUSABLE, detail=str(error)) from error
    return data


def _wire(ctx: "Context") -> tuple[Done, Registry]:
    """``sync_links`` from the registry; unusable: links left as they are."""
    with locks.registry_lock(ctx):
        try:
            registry = config.load(ctx)
        except RegistryError as error:
            raise MounterError(WIRING_UNCHANGED, detail=error.detail) from error
        change = wiring.sync_links(ctx, registry)
    if not (change.created or change.removed):
        return skipped(), registry
    detail = f"{len(change.created)} created, {len(change.removed)} removed"
    return ok(detail), registry


def _daemon_reload(ctx: "Context") -> Done:
    systemd.daemon_reload(ctx)
    return ok()


# --- 10. to 12. starts, mount base, prune -----------------------------------------


def _start(ctx: "Context", steps: Steps, registry: Registry | None) -> None:
    if registry is None:
        steps.add("start", "skipped", WIRING_UNCHANGED)
        return
    start_present(ctx, steps, registry)


def _mount_base(ctx: "Context") -> Done:
    base = ctx.platform.mount_base
    existed = os.path.lexists(ctx.paths.p(base))
    mountdirs.ensure_mount_base(ctx)
    return skipped(base) if existed else ok(base)


def _prune(ctx: "Context", chosen: _Release) -> Done:
    """Keep ``current`` and the release installed just before it; delete the rest.

    "Before" is by the UTC stamp ``install.sh`` appends (``<version>-<stamp>``,
    fixed width), not by the whole name: name order puts ``0.10.0`` before
    ``0.9.0`` and would delete the previous release at that upgrade, and no
    version scheme is assumed. The stamp is install order, so after a
    downgrade the release kept is the one that was active before it.
    ``current`` is the running release (step 2 checked that), so a partial
    release left by a failed later ``install.sh`` run goes too, as does
    anything without a stamp.
    """
    releases = ctx.paths.p(RELEASES_DIR)
    names = sorted(os.listdir(releases))
    keep = {chosen.name}
    current = _stamp(chosen.name)
    older = sorted(
        (stamp, name)
        for name in names
        if (stamp := _stamp(name)) is not None
        and current is not None
        and stamp < current
    )
    if older:
        keep.add(older[-1][1])
    removed = [name for name in names if name not in keep]
    for name in removed:
        remove_path(releases / name)
    return ok(f"removed {', '.join(removed)}") if removed else skipped()


def _stamp(name: str) -> str | None:
    """The ``YYYYMMDDTHHMMSSZ`` suffix of a release name, or None."""
    found = RELEASE_STAMP.search(name)
    return found.group(1) if found else None
