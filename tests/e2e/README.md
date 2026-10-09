# On-device E2E journeys

The files in this directory check steamos-mounter on the owner's Steam Deck: eight user journeys in
`test_on_device_journeys.py` (Stage A on scratch images, Stage B on real drives, Stage C after a SteamOS update) and
the host-side harness that runs their read-only checks over SSH (`conftest.py`, `test_deck_harness.py`).

Design Doc reference: `docs/design/steamos-mounter-design.md`, sections "On-device Verification Procedure",
"Early Verification Point" (EVP-2) and "Output Comparison".

## Running the journeys

Run from the repository root **on the development host**, never in Docker:

```console
STEAMOS_MOUNTER_DECK=1 \
STEAMOS_MOUNTER_DECK_SSH="ssh -o BatchMode=yes -p 2222 deck@10.0.1.100" \
pytest --no-cov tests/e2e
```

- `STEAMOS_MOUNTER_DECK=1` turns the journeys on. Without it every journey and `test_deck_reachable` is skipped.
- `STEAMOS_MOUNTER_DECK_SSH` is the SSH prefix the harness puts in front of every check. When unset, the harness
  uses `ssh -o BatchMode=yes -p 2222 deck@10.0.1.100` (`DEFAULT_SSH` in the journey module). A custom prefix must
  have this shape, or the `deck` fixture raises `ValueError` before any process starts:

  ```text
  ssh [-4] [-6] [-q] [-p PORT] [-i FILE] [-l USER] [-F FILE] [-o KEY=VALUE] destination
  ```

  - The program is `ssh` or an absolute path to it (`/usr/bin/ssh`), never a relative path such as `./ssh`, so a
    check cannot run on the host by mistake.
  - Only the options above, each value as a separate word: `-p 2222`, not `-p2222`. `-o` accepts `BatchMode`,
    `ConnectTimeout`, `StrictHostKeyChecking` and `UserKnownHostsFile` only, and `StrictHostKeyChecking` only with
    `yes` or `accept-new` (any case). This keeps out options that exit 0 without connecting (`-V`, `-G`, which would
    fake a reachability pass), `-o ProxyCommand`, which runs a local command, and `StrictHostKeyChecking=no`, which
    skips the host key check.
  - Exactly one destination, as the last word. Extra words would run on the Deck before the allow-listed check.
- The host needs Python 3.11 or newer with the dev tools installed (`pip install -r requirements-dev.txt` in a
  virtual environment). `pytest-cov` is needed even with `--no-cov`, because `pyproject.toml` passes `--cov` options.
- Run the stages in order: Stage B only after Stage A passed, Stage C only after Stage B. Select one with `-k`, for
  example `-k stage_a`.
- Check the connection first: `pytest --no-cov tests/e2e -k deck_reachable` with the two variables set.

### Why `--no-cov`

`pyproject.toml` adds `--cov=steamos_mounter --cov-fail-under=95` to every pytest run. The journeys import nothing
from the package (the code under test runs on the Deck), so coverage would be 0 % and the run would fail on the gate
even when every journey passed.

### Why never in Docker

The journeys need the Deck, physical actions (plugging and unplugging drives, typing a key) and the owner's `sudo`.
The container has none of these. In Docker (`docker compose run --rm dev pytest --no-cov tests/e2e`) every journey
and `test_deck_reachable` are reported as skipped by the environment guard; only the Docker-safe harness tests in
`test_deck_harness.py` run, with `subprocess.run` stubbed, so nothing tries SSH.

## Owner prerequisites

Before every session:

1. **Confirm the Deck's IP address first.** It comes from DHCP and changes. Put the current address in
   `STEAMOS_MOUNTER_DECK_SSH`.
1. SSH works without a password prompt: a key is installed for `deck`, sshd listens on port 2222, and this succeeds
   on the host:

   ```console
   ssh -o BatchMode=yes -o ConnectTimeout=5 -p 2222 deck@<IP> true
   ```

1. The Deck is in **Desktop Mode** (Game Mode items are deferred by the owner).
1. The latest committed build is installed with `sudo ./install.sh` when the journey needs it (Stage A step 3 does
   the first install).
1. The drives and images for the journey are at hand:

| Journey | Needs |
| --- | --- |
| Stage A: scratch images, register, mount, reload | `clean.img`, `dirty.img`, `unsafe.img` (built in Docker by `tools/make_scratch_images.sh`) copied to `~/steamos-mounter-scratch/`; no external drive attached |
| Stage B: plug-in, unplug, replug | the WD drive with MEDIABOX and PERSONAL registered (PERSONAL's key stored); a dock and a hub |
| Stage B: reboot with and without the drive | the WD drive |
| Stage B: key dialog | the WD drive; PERSONAL's stored key removed before each trial |
| Stage B: Dolphin unlock | a second, unregistered BitLocker drive; the WD drive; an exFAT or FAT stick labelled `GAMES` |
| Stage B: safely remove | the WD drive |
| Stage B: remove, update, uninstall | the WD drive; the `SCRATCH` loop registration from Stage A |
| Stage C: SteamOS update survival | the WD drive attached through the update |

## Division of labour

From the Design Doc's "Who does what":

- **The owner** runs every `sudo` step and every physical action: installing, `losetup`, `add` and `remove`,
  plugging and unplugging, typing a key, rebooting, applying the SteamOS update.
- **The harness** only reads. The `deck` fixture runs a command over SSH only when it is exactly one of:
  - a value of `READ_ONLY_CHECKS` in `test_on_device_journeys.py` (imported, not copied);
  - `true`, the reachability check;
  - one of the read-only `sudo -n` listings the journeys name: `ls -l` of the key directory, `cat` of
    `/etc/steamos-mounter/config.toml`, and `stat` (owner and mode only) of the key directory and PERSONAL's key file.

  Any other string raises `ValueError` before a process starts. `sudo -n` never prompts: without a cached credential
  it exits 1 and runs nothing. Each call has a 60 s timeout, closes stdin (so ssh never reads the terminal the owner
  answers on) and returns the completed process whatever its exit code; the journeys assert on it.
- To add a check, add it to `READ_ONLY_CHECKS` in the journey module, and only if it writes nothing on the Deck.

## Seed data, authentication and mocks

All owner-side; nothing is mocked and there is no CI seed script, because every seed step needs `sudo` on the Deck:

- **Seed data**: the scratch images under `~/steamos-mounter-scratch/` and the `SCRATCH` loop registration (Stage A);
  the MEDIABOX and PERSONAL registrations for Stage B.
- **Authentication**: the owner's SSH key for `deck` (BatchMode) and the owner's own `sudo` password, typed on the
  Deck, never passed to the harness.
- **External services**: none. The journeys run against the real Deck.

## Trial log

Each session's captures and results go to `docs/plans/steamos-mounter-on-device-log.md`. It is a local file: `docs/`
is in `.gitignore`, so the log is never committed.
