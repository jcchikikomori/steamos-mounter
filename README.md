# steamos-mounter

Mount external drives on SteamOS at plug-in and boot, and keep the setup through SteamOS updates.

Status: under development. Install steps, commands, limitations and troubleshooting are added before the first
release.

## Development

Every check runs in Docker. The `dev` service uses Python 3.14 and the `floor` service uses Python 3.11, the oldest
supported version. Both run as your host user, so files written into the checkout stay yours.

```bash
docker compose build
docker compose run --rm dev pytest
docker compose run --rm dev ruff check .
docker compose run --rm dev ruff format --check .
docker compose run --rm dev shellcheck -s sh install.sh uninstall.sh tools/make_scratch_images.sh
docker compose run --rm floor pytest -p no:cacheprovider
```

If your user ID or group ID is not 1000, export `UID` and `GID` before running these commands.
