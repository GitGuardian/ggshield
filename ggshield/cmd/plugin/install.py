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
    PluginsNotEnabledError,
    PluginSourceType,
)
from ggshield.core.plugin.downloader import (
    ChecksumMismatchError,
    GitHubArtifactError,
    InsecureSourceError,
    PluginDownloader,
)
from ggshield.core.plugin.loader import resolve_config_key
from ggshield.core.plugin.platform import get_platform_info
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
    return PluginSourceType.PLATFORM


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
    # Signature verification is strict by default. The only override is the
    # explicit per-command --allow-unsigned flag.
    signature_mode = (
        SignatureVerificationMode.WARN
        if allow_unsigned
        else SignatureVerificationMode.STRICT
    )

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


def _enable_installed_plugin(
    enterprise_config: EnterpriseConfig,
    plugin_name: str,
    version: str,
    wheel_path: Path,
) -> str:
    """Enable the canonical plugin key and remove stale package-name config."""
    config_key = resolve_config_key(wheel_path, fallback=plugin_name)
    if config_key != plugin_name:
        enterprise_config.remove_plugin(plugin_name)
    enterprise_config.enable_plugin(config_key, version=version)
    return config_key


def _install_from_gitguardian(
    ctx: click.Context,
    plugin_name: str,
    version: Optional[str],
    signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
) -> None:
    """Install a plugin from the GitGuardian platform."""
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config

    try:
        client = create_client_from_config(config)
        plugin_api_client = PluginAPIClient(client)
        catalog = plugin_api_client.get_available_plugins()
    except PluginsNotEnabledError:
        ui.display_error(
            "Plugin system is not available on this workspace. "
            "Contact your administrator."
        )
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except PluginAPIError as e:
        ui.display_error(str(e))
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except Exception as e:
        ui.display_error(f"Failed to connect to GitGuardian: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)

    available_plugins = {p.name: p for p in catalog.plugins if p.available}

    if plugin_name not in available_plugins:
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

    downloader = PluginDownloader()
    enterprise_config = EnterpriseConfig.load()
    platform_info = get_platform_info()

    ui.display_info(f"Installing {plugin_name}...")

    try:
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
                    # In STRICT mode, an unreachable bundle is a hard
                    # failure — the user expects signature verification.
                    # In WARN mode they have opted into accepting
                    # unsigned plugins, so a bundle the proxy couldn't
                    # serve is equivalent to "no signature available"
                    # rather than a reason to abort an otherwise valid
                    # wheel download.
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

        installed_name = _enable_installed_plugin(
            enterprise_config, plugin_name, info.version, wheel_path
        )
        enterprise_config.save()
        ui.display_info(f"Installed {installed_name} v{info.version}")

    except SignatureVerificationError as e:
        ui.display_error(f"Signature verification failed for {plugin_name}: {e}")
        ui.display_info(
            "This plugin is not signed by GitGuardian. "
            "If you trust its origin and still want to install it, "
            "pass --allow-unsigned."
        )
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except Exception as e:
        ui.display_error(f"Failed to install {plugin_name}: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)

    plugin_api_client.report_installation(
        plugin_name, info.version, platform_info.os, platform_info.arch
    )


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
        plugin_name, version, installed_wheel = downloader.install_from_wheel(
            wheel_path, signature_mode=signature_mode
        )

        plugin_name = _enable_installed_plugin(
            enterprise_config, plugin_name, version, installed_wheel
        )
        enterprise_config.save()

        ui.display_info(f"Installed {plugin_name} v{version}")

    except SignatureVerificationError as e:
        ui.display_error(f"Signature verification failed: {e}")
        ui.display_info(
            "This plugin is not signed by GitGuardian. "
            "If you trust its origin and still want to install it, "
            "pass --allow-unsigned."
        )
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
        plugin_name, version, installed_wheel = downloader.download_from_url(
            url, sha256, signature_mode=signature_mode
        )

        plugin_name = _enable_installed_plugin(
            enterprise_config, plugin_name, version, installed_wheel
        )
        enterprise_config.save()

        ui.display_info(f"Installed {plugin_name} v{version}")

    except SignatureVerificationError as e:
        ui.display_error(f"Signature verification failed: {e}")
        ui.display_info(
            "This plugin is not signed by GitGuardian. "
            "If you trust its origin and still want to install it, "
            "pass --allow-unsigned."
        )
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except InsecureSourceError as e:
        ui.display_error(str(e))
        ctx.exit(ExitCode.USAGE_ERROR)
    except ChecksumMismatchError as e:
        ui.display_error(f"Checksum verification failed: {e}")
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
        plugin_name, version, installed_wheel = downloader.download_from_github_release(
            url, sha256, signature_mode=signature_mode
        )

        plugin_name = _enable_installed_plugin(
            enterprise_config, plugin_name, version, installed_wheel
        )
        enterprise_config.save()

        ui.display_info(f"Installed {plugin_name} v{version}")

    except SignatureVerificationError as e:
        ui.display_error(f"Signature verification failed: {e}")
        ui.display_info(
            "This plugin is not signed by GitGuardian. "
            "If you trust its origin and still want to install it, "
            "pass --allow-unsigned."
        )
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except InsecureSourceError as e:
        ui.display_error(str(e))
        ctx.exit(ExitCode.USAGE_ERROR)
    except ChecksumMismatchError as e:
        ui.display_error(f"Checksum verification failed: {e}")
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
        plugin_name, version, installed_wheel = (
            downloader.download_from_github_artifact(url, signature_mode=signature_mode)
        )

        plugin_name = _enable_installed_plugin(
            enterprise_config, plugin_name, version, installed_wheel
        )
        enterprise_config.save()

        ui.display_info(f"Installed {plugin_name} v{version}")

    except SignatureVerificationError as e:
        ui.display_error(f"Signature verification failed: {e}")
        ui.display_info(
            "This plugin is not signed by GitGuardian. "
            "If you trust its origin and still want to install it, "
            "pass --allow-unsigned."
        )
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except GitHubArtifactError as e:
        ui.display_error(str(e))
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except Exception as e:
        ui.display_error(f"Failed to install from GitHub artifact: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
