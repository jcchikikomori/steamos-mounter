"""Platform selection. Only SteamOS is supported (DD-30: checked first)."""

from steamos_mounter.errors import UnsupportedPlatformError
from steamos_mounter.platforms.base import HostPaths, Platform
from steamos_mounter.platforms.steamos import OS_RELEASE, SteamOSPlatform

UNSUPPORTED_MESSAGE = "unsupported platform: SteamOS only"


def current_platform(paths: HostPaths | None = None) -> Platform:
    """The platform of the host at ``paths`` (default ``/``).

    Raises ``UnsupportedPlatformError`` (exit 4) anywhere but SteamOS.
    """
    host = HostPaths() if paths is None else paths
    platform = SteamOSPlatform()
    if not platform.detect(host):
        raise UnsupportedPlatformError(
            UNSUPPORTED_MESSAGE, detail=f"{host.p(OS_RELEASE)} has no ID=steamos"
        )
    return platform
