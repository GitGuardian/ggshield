"""
Install a plugin from the GitGuardian platform.

Shared by `ggshield plugin install <name>` and `ggshield machine setup`. The
command turns every failure into a non-zero exit; setup keeps going and reports.
Only the mechanics live here — download, verify, unpack, enable — so each caller
decides what a failure means.
"""

from dataclasses import dataclass
from typing import Optional

from ggshield.core import ui
from ggshield.core.config.enterprise_config import EnterpriseConfig
from ggshield.core.plugin.client import PluginAPIClient, PluginAPIError
from ggshield.core.plugin.downloader import PluginDownloader
from ggshield.core.plugin.loader import enable_installed_plugin
from ggshield.core.plugin.platform import PlatformInfo, get_platform_info
from ggshield.core.plugin.signature import SignatureVerificationMode


@dataclass
class InstalledPlugin:
    """A plugin that was just installed and enabled."""

    name: str  # canonical config key it was enabled under, not the catalog reference
    version: str


def install_plugin_from_platform(
    plugin_api_client: PluginAPIClient,
    plugin_name: str,
    *,
    version: Optional[str] = None,
    signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
    downloader: Optional[PluginDownloader] = None,
    enterprise_config: Optional[EnterpriseConfig] = None,
    platform_info: Optional[PlatformInfo] = None,
) -> InstalledPlugin:
    """Download, verify and enable ``plugin_name`` from the platform catalog.

    The caller is expected to have checked the plugin is available for the
    account; this goes straight to the download endpoint, which enforces
    entitlement server-side anyway (403 -> ``PluginNotAvailableError``).

    ``downloader`` and ``enterprise_config`` can be passed in so a caller
    installing several plugins in a row reuses one of each.

    Raises:
        PluginNotAvailableError: The account cannot install this plugin.
        PluginAPIError: The platform call failed.
        SignatureVerificationError: STRICT mode and the signature is invalid.
        DownloadError, ChecksumMismatchError: The wheel could not be installed.
    """
    downloader = downloader if downloader is not None else PluginDownloader()
    if enterprise_config is None:
        enterprise_config = EnterpriseConfig.load()
    if platform_info is None:
        platform_info = get_platform_info()

    with plugin_api_client.download_plugin(
        plugin_name, platform_info=platform_info, version=version
    ) as (info, chunks):
        bundle_bytes: Optional[bytes] = None
        if info.signature_url:
            try:
                bundle_bytes = plugin_api_client.download_signature_bundle(
                    info.signature_url
                )
            except PluginAPIError as bundle_err:
                # In STRICT mode, an unreachable bundle is a hard failure — the
                # caller expects signature verification. In WARN mode they have
                # opted into accepting unsigned plugins, so a bundle the proxy
                # couldn't serve is equivalent to "no signature available"
                # rather than a reason to abort an otherwise valid download.
                if signature_mode == SignatureVerificationMode.STRICT:
                    raise
                ui.display_warning(
                    f"Could not fetch signature bundle for {plugin_name}: "
                    f"{bundle_err}. Continuing without verification "
                    f"(--allow-unsigned)."
                )
        wheel_path = downloader.download_and_install(
            info,
            chunks,
            plugin_name,
            signature_mode=signature_mode,
            bundle_bytes=bundle_bytes,
        )

    installed_name = enable_installed_plugin(
        enterprise_config, plugin_name, info.version, wheel_path
    )
    enterprise_config.save()
    return InstalledPlugin(name=installed_name, version=info.version)
