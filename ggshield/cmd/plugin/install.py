"""
Plugin install command.
"""

import re
from pathlib import Path
from typing import Any, Optional

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.config.enterprise_config import EnterpriseConfig
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.client import (
    PluginAPIClient,
    PluginAPIError,
    PluginNotAvailableError,
    PluginSourceType,
)
from ggshield.core.plugin.downloader import (
    ChecksumMismatchError,
    DownloadError,
    GitHubArtifactError,
    InsecureSourceError,
    PluginDownloader,
)
from ggshield.core.plugin.signature import (
    SignatureVerificationError,
    SignatureVerificationMode,
)


def detect_source_type(plugin_source: str) -> PluginSourceType:
    """
    Detect the type of plugin source from the argument.

    Detection order:
    1. GitHub artifact URL: github.com/.../actions/runs/.../artifacts/...
    2. GitHub release URL: github.com/.../releases/download/...
    3. Generic URL: starts with http:// or https://
    4. Local wheel file: path exists and ends with .whl
    5. Plugin name: everything else -> GitGuardian API
    """
    if plugin_source.startswith(("http://", "https://")):
        # GitHub Actions artifact
        if re.match(
            r"https://github\.com/[^/]+/[^/]+/actions/runs/\d+/artifacts/\d+",
            plugin_source,
        ):
            return PluginSourceType.GITHUB_ARTIFACT
        # GitHub release asset
        if re.match(
            r"https://github\.com/[^/]+/[^/]+/releases/download/",
            plugin_source,
        ):
            return PluginSourceType.GITHUB_RELEASE
        # Any other URL
        return PluginSourceType.URL

    # Check if it's a local wheel file
    if plugin_source.endswith(".whl"):
        return PluginSourceType.LOCAL_FILE

    # Default: assume it's a plugin name for GitGuardian API
    return PluginSourceType.GITGUARDIAN_API


@click.command()
@click.argument("plugin_source")
@click.option(
    "--version",
    "version",
    default=None,
    help="Specific version to install (GitGuardian API only)",
)
@click.option(
    "--sha256",
    "sha256",
    default=None,
    help="Expected SHA256 checksum for URL verification",
)
@click.option(
    "--allow-unsigned",
    "allow_unsigned",
    is_flag=True,
    help="Allow installing plugins without valid signatures (overrides strict mode)",
)
@add_common_options()
@click.pass_context
def install_cmd(
    ctx: click.Context,
    plugin_source: str,
    version: Optional[str],
    sha256: Optional[str],
    allow_unsigned: bool,
    **kwargs: Any,
) -> None:
    """
    Download and install a plugin.

    Install from GitGuardian (requires authentication):

        ggshield plugin install tokenscanner

        ggshield plugin install tokenscanner --version 0.1.0

    Install from a local wheel file:

        ggshield plugin install ./path/to/plugin.whl

    Install from a URL:

        ggshield plugin install https://example.com/plugin.whl

        ggshield plugin install https://example.com/plugin.whl --sha256 abc123...

    Install from a GitHub release:

        ggshield plugin install https://github.com/owner/repo/releases/download/v1.0.0/plugin.whl

    Install from a GitHub Actions artifact (requires GITHUB_TOKEN):

        ggshield plugin install https://github.com/owner/repo/actions/runs/123/artifacts/456
    """
    # Determine signature verification mode
    enterprise_config = EnterpriseConfig.load()
    signature_mode = enterprise_config.get_signature_mode()
    if allow_unsigned:
        signature_mode = SignatureVerificationMode.WARN

    source_type = detect_source_type(plugin_source)

    if source_type == PluginSourceType.GITHUB_ARTIFACT:
        _install_from_github_artifact(ctx, plugin_source, signature_mode)
    elif source_type == PluginSourceType.GITHUB_RELEASE:
        _install_from_github_release(ctx, plugin_source, sha256, signature_mode)
    elif source_type == PluginSourceType.URL:
        _install_from_url(ctx, plugin_source, sha256, signature_mode)
    elif source_type == PluginSourceType.LOCAL_FILE:
        _install_from_local_wheel(ctx, plugin_source, signature_mode)
    else:
        _install_from_gitguardian(ctx, plugin_source, version, signature_mode)


def _install_from_gitguardian(
    ctx: click.Context,
    plugin_name: str,
    version: Optional[str],
    signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
) -> None:
    """Install a plugin from GitGuardian API."""
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config

    # Fetch available plugins
    try:
        client = create_client_from_config(config)
        plugin_api_client = PluginAPIClient(client)
        catalog = plugin_api_client.get_available_plugins()
    except PluginAPIError as e:
        ui.display_error(str(e))
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except Exception as e:
        ui.display_error(f"Failed to connect to GitGuardian: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)

    # Check if plugin is available
    available_plugins = {p.name: p for p in catalog.plugins if p.available}

    if plugin_name not in available_plugins:
        # Check if plugin exists but is not available
        unavailable = next((p for p in catalog.plugins if p.name == plugin_name), None)
        if unavailable:
            ui.display_error(
                f"Plugin '{plugin_name}' is not available for your account"
            )
            if unavailable.reason:
                ui.display_info(f"Reason: {unavailable.reason}")
        else:
            ui.display_error(f"Unknown plugin: {plugin_name}")
            ui.display_info("Use 'ggshield plugin status' to see available plugins")
        ctx.exit(ExitCode.USAGE_ERROR)

    # Install the plugin
    downloader = PluginDownloader()
    enterprise_config = EnterpriseConfig.load()

    ui.display_info(f"Installing {plugin_name}...")

    try:
        # Get download info
        download_info = plugin_api_client.get_download_info(
            plugin_name, version=version
        )

        # Download and install
        downloader.download_and_install(
            download_info, plugin_name, signature_mode=signature_mode
        )

        # Enable in config
        enterprise_config.enable_plugin(plugin_name, version=download_info.version)

        # Save config
        enterprise_config.save()

        ui.display_info(f"Installed {plugin_name} v{download_info.version}")

    except SignatureVerificationError as e:
        ui.display_error(f"Signature verification failed for {plugin_name}: {e}")
        ui.display_info(
            "Use --allow-unsigned to install without signature verification"
        )
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except PluginNotAvailableError as e:
        ui.display_error(f"Failed to install {plugin_name}: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except DownloadError as e:
        ui.display_error(f"Failed to install {plugin_name}: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except Exception as e:
        ui.display_error(f"Failed to install {plugin_name}: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)


def _install_from_local_wheel(
    ctx: click.Context,
    wheel_path_str: str,
    signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
) -> None:
    """Install a plugin from a local wheel file."""
    wheel_path = Path(wheel_path_str)

    if not wheel_path.exists():
        ui.display_error(f"Wheel file not found: {wheel_path}")
        ctx.exit(ExitCode.USAGE_ERROR)

    downloader = PluginDownloader()
    enterprise_config = EnterpriseConfig.load()

    ui.display_info(f"Installing from {wheel_path.name}...")

    try:
        plugin_name, version, _ = downloader.install_from_wheel(
            wheel_path, signature_mode=signature_mode
        )

        # Enable in config
        enterprise_config.enable_plugin(plugin_name, version=version)
        enterprise_config.save()

        ui.display_info(f"Installed {plugin_name} v{version}")

    except SignatureVerificationError as e:
        ui.display_error(f"Signature verification failed: {e}")
        ui.display_info(
            "Use --allow-unsigned to install without signature verification"
        )
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except DownloadError as e:
        ui.display_error(f"Failed to install from wheel: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except Exception as e:
        ui.display_error(f"Failed to install from wheel: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)


def _install_from_url(
    ctx: click.Context,
    url: str,
    sha256: Optional[str],
    signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
) -> None:
    """Install a plugin from a URL."""
    downloader = PluginDownloader()
    enterprise_config = EnterpriseConfig.load()

    ui.display_info("Installing from URL...")

    try:
        plugin_name, version, _ = downloader.download_from_url(
            url, sha256, signature_mode=signature_mode
        )

        # Enable in config
        enterprise_config.enable_plugin(plugin_name, version=version)
        enterprise_config.save()

        ui.display_info(f"Installed {plugin_name} v{version}")

    except SignatureVerificationError as e:
        ui.display_error(f"Signature verification failed: {e}")
        ui.display_info(
            "Use --allow-unsigned to install without signature verification"
        )
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except InsecureSourceError as e:
        ui.display_error(str(e))
        ctx.exit(ExitCode.USAGE_ERROR)
    except ChecksumMismatchError as e:
        ui.display_error(f"Checksum verification failed: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except DownloadError as e:
        ui.display_error(f"Failed to install from URL: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except Exception as e:
        ui.display_error(f"Failed to install from URL: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)


def _install_from_github_release(
    ctx: click.Context,
    url: str,
    sha256: Optional[str],
    signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
) -> None:
    """Install a plugin from a GitHub release asset."""
    downloader = PluginDownloader()
    enterprise_config = EnterpriseConfig.load()

    ui.display_info("Installing from GitHub release...")

    try:
        plugin_name, version, _ = downloader.download_from_github_release(
            url, sha256, signature_mode=signature_mode
        )

        # Enable in config
        enterprise_config.enable_plugin(plugin_name, version=version)
        enterprise_config.save()

        ui.display_info(f"Installed {plugin_name} v{version}")

    except SignatureVerificationError as e:
        ui.display_error(f"Signature verification failed: {e}")
        ui.display_info(
            "Use --allow-unsigned to install without signature verification"
        )
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except InsecureSourceError as e:
        ui.display_error(str(e))
        ctx.exit(ExitCode.USAGE_ERROR)
    except ChecksumMismatchError as e:
        ui.display_error(f"Checksum verification failed: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except DownloadError as e:
        ui.display_error(f"Failed to install from GitHub release: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except Exception as e:
        ui.display_error(f"Failed to install from GitHub release: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)


def _install_from_github_artifact(
    ctx: click.Context,
    url: str,
    signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
) -> None:
    """Install a plugin from a GitHub Actions artifact."""
    ui.display_warning("GitHub artifacts are ephemeral and cannot be auto-updated.")

    downloader = PluginDownloader()
    enterprise_config = EnterpriseConfig.load()

    ui.display_info("Installing from GitHub artifact...")

    try:
        plugin_name, version, _ = downloader.download_from_github_artifact(
            url, signature_mode=signature_mode
        )

        # Enable in config
        enterprise_config.enable_plugin(plugin_name, version=version)
        enterprise_config.save()

        ui.display_info(f"Installed {plugin_name} v{version}")

    except SignatureVerificationError as e:
        ui.display_error(f"Signature verification failed: {e}")
        ui.display_info(
            "Use --allow-unsigned to install without signature verification"
        )
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except GitHubArtifactError as e:
        ui.display_error(str(e))
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except DownloadError as e:
        ui.display_error(f"Failed to install from GitHub artifact: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except Exception as e:
        ui.display_error(f"Failed to install from GitHub artifact: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
