"""
Plugin update command - updates installed plugins.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import click
import requests
from packaging import version as packaging_version

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
from ggshield.core.plugin.downloader import DownloadError, PluginDownloader
from ggshield.core.plugin.loader import PluginLoader
from ggshield.core.text_utils import pluralize


logger = logging.getLogger(__name__)


def _is_newer_version(installed_version: str, candidate_version: str) -> bool:
    """Return True if candidate version is newer than installed version."""
    try:
        return packaging_version.parse(installed_version) < packaging_version.parse(
            candidate_version
        )
    except Exception as e:
        logger.warning(
            "Failed to parse plugin versions '%s' and '%s': %s",
            installed_version,
            candidate_version,
            e,
        )
        return False


@click.command()
@click.argument("plugin_name", required=False)
@click.option(
    "--all",
    "update_all",
    is_flag=True,
    help="Update all installed plugins",
)
@click.option(
    "--check",
    "check_only",
    is_flag=True,
    help="Check for updates without installing",
)
@add_common_options()
@click.pass_context
def update_cmd(
    ctx: click.Context,
    plugin_name: Optional[str],
    update_all: bool,
    check_only: bool,
    **kwargs: Any,
) -> None:
    """
    Update installed plugins.

    Check for available updates:

        ggshield plugin update --check

    Update a specific plugin:

        ggshield plugin update tokenscanner

    Update all installed plugins:

        ggshield plugin update --all

    Note: Only plugins from GitGuardian API and GitHub releases can be auto-updated.
    Plugins installed from local files or GitHub artifacts cannot be auto-updated.
    """
    if not plugin_name and not update_all and not check_only:
        ui.display_error("Please specify a plugin name, use --all, or use --check")
        ui.display_info("Usage: ggshield plugin update <plugin_name>")
        ui.display_info("       ggshield plugin update --all")
        ui.display_info("       ggshield plugin update --check")
        ctx.exit(ExitCode.USAGE_ERROR)

    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config

    # Get installed plugins
    enterprise_config = EnterpriseConfig.load()
    loader = PluginLoader(enterprise_config)
    downloader = PluginDownloader()

    installed_plugins = {p.name: p for p in loader.discover_plugins() if p.is_installed}

    # Determine which plugins to check/update
    if update_all or check_only:
        plugins_to_process = list(installed_plugins.keys())
    else:
        if plugin_name not in installed_plugins:
            ui.display_error(f"Plugin '{plugin_name}' is not installed")
            ui.display_info("Use 'ggshield plugin list' to see installed plugins")
            ctx.exit(ExitCode.USAGE_ERROR)
        plugins_to_process = [plugin_name]

    if not plugins_to_process:
        ui.display_info("No plugins installed.")
        ui.display_info("Use 'ggshield plugin install' to install plugins.")
        return

    # Categorize plugins by source type
    gitguardian_plugins: List[str] = []
    github_release_plugins: List[str] = []
    non_updatable_plugins: List[Dict[str, Any]] = []

    for name in plugins_to_process:
        source = downloader.get_plugin_source(name)
        if source is None:
            # Legacy manifest or unknown source - try GitGuardian API
            gitguardian_plugins.append(name)
        elif source.type == PluginSourceType.GITGUARDIAN_API:
            gitguardian_plugins.append(name)
        elif source.type == PluginSourceType.GITHUB_RELEASE:
            github_release_plugins.append(name)
        else:
            # Local file, URL, or artifact - cannot auto-update
            non_updatable_plugins.append(
                {
                    "name": name,
                    "source_type": source.type.value,
                }
            )

    # Check GitGuardian API for updates
    updates_available: List[Dict[str, Any]] = []
    plugin_api_client: Optional[PluginAPIClient] = None

    if gitguardian_plugins:
        try:
            client = create_client_from_config(config)
            plugin_api_client = PluginAPIClient(client)
            catalog = plugin_api_client.get_available_plugins()
            available_plugins = {p.name: p for p in catalog.plugins if p.available}

            for name in gitguardian_plugins:
                installed = installed_plugins.get(name)
                available = available_plugins.get(name)

                if not installed or not available:
                    continue

                installed_version = installed.version
                latest_version = available.latest_version

                if (
                    installed_version
                    and latest_version
                    and _is_newer_version(installed_version, latest_version)
                ):
                    updates_available.append(
                        {
                            "name": name,
                            "installed_version": installed_version,
                            "latest_version": latest_version,
                            "source_type": PluginSourceType.GITGUARDIAN_API,
                        }
                    )

        except PluginAPIError as e:
            ui.display_error(str(e))
            ctx.exit(ExitCode.UNEXPECTED_ERROR)
        except Exception as e:
            ui.display_error(f"Failed to connect to GitGuardian: {e}")
            ctx.exit(ExitCode.UNEXPECTED_ERROR)

    # Check GitHub releases for updates
    for name in github_release_plugins:
        source = downloader.get_plugin_source(name)
        if not source or not source.github_repo:
            continue

        installed = installed_plugins.get(name)
        if not installed or not installed.version:
            continue

        latest_release = _check_github_release_update(source.github_repo)
        if latest_release:
            latest_version = latest_release.get("tag_name", "").lstrip("v")
            if latest_version and _is_newer_version(installed.version, latest_version):
                # Find wheel asset in release
                wheel_url = _find_wheel_asset(latest_release)
                if wheel_url:
                    updates_available.append(
                        {
                            "name": name,
                            "installed_version": installed.version,
                            "latest_version": latest_version,
                            "source_type": PluginSourceType.GITHUB_RELEASE,
                            "download_url": wheel_url,
                            "github_repo": source.github_repo,
                        }
                    )

    # Check-only mode
    if check_only:
        if updates_available:
            ui.display_heading("Updates Available")
            for update in updates_available:
                source_label = (
                    "GitGuardian"
                    if update["source_type"] == PluginSourceType.GITGUARDIAN_API
                    else "GitHub"
                )
                ui.display_info(
                    f"  {update['name']}: {update['installed_version']} -> "
                    f"{update['latest_version']} ({source_label})"
                )
            ui.display_info("")
            ui.display_info("Run 'ggshield plugin update --all' to update.")
        else:
            ui.display_info("All updatable plugins are up to date.")

        if non_updatable_plugins:
            ui.display_info("")
            ui.display_heading("Cannot Auto-Update")
            for plugin in non_updatable_plugins:
                ui.display_info(
                    f"  {plugin['name']}: installed from {plugin['source_type']}"
                )
            ui.display_info("Re-install these plugins manually to update.")
        return

    # Update mode
    if not updates_available:
        if plugin_name:
            # Check if it's non-updatable
            source = downloader.get_plugin_source(plugin_name)
            if source and source.type not in (
                PluginSourceType.GITGUARDIAN_API,
                PluginSourceType.GITHUB_RELEASE,
            ):
                ui.display_error(
                    f"Plugin '{plugin_name}' was installed from {source.type.value} "
                    "and cannot be auto-updated."
                )
                ui.display_info("Re-install the plugin manually to update.")
                ctx.exit(ExitCode.USAGE_ERROR)
            ui.display_info(f"Plugin '{plugin_name}' is already up to date.")
        else:
            ui.display_info("All updatable plugins are already up to date.")
        return

    success_count = 0
    error_count = 0

    for update in updates_available:
        name = update["name"]
        latest_version = update["latest_version"]
        source_type = update["source_type"]

        ui.display_info(
            f"Updating {name}: {update['installed_version']} -> {latest_version}..."
        )

        try:
            updated = False

            if source_type == PluginSourceType.GITGUARDIAN_API:
                assert plugin_api_client is not None
                # Get download info from API
                download_info = plugin_api_client.get_download_info(
                    name, version=latest_version
                )

                # Download and install (overwrites existing)
                downloader.download_and_install(download_info, name)
                updated = True

            elif source_type == PluginSourceType.GITHUB_RELEASE:
                # Download from GitHub release URL
                download_url = update.get("download_url")
                github_repo = update.get("github_repo")
                if not download_url or not github_repo:
                    raise DownloadError(
                        "Missing GitHub release metadata for plugin update"
                    )

                downloader.download_from_github_release(download_url)
                updated = True

            else:
                raise DownloadError(f"Unsupported plugin source type: {source_type}")

            if not updated:
                raise DownloadError("Plugin update was skipped")

            # Update config
            enterprise_config.enable_plugin(name, version=latest_version)

            ui.display_info(f"  Updated {name} to v{latest_version}")
            success_count += 1

        except PluginNotAvailableError as e:
            ui.display_error(f"  Failed to update {name}: {e}")
            error_count += 1
        except DownloadError as e:
            ui.display_error(f"  Failed to update {name}: {e}")
            error_count += 1
        except Exception as e:
            ui.display_error(f"  Failed to update {name}: {e}")
            error_count += 1

    # Save config
    enterprise_config.save()

    # Summary
    if success_count > 0:
        ui.display_info("")
        ui.display_info(
            f"{success_count} {pluralize('plugin', success_count)} updated successfully."
        )

    if non_updatable_plugins and update_all:
        ui.display_info("")
        ui.display_info(
            f"{len(non_updatable_plugins)} {pluralize('plugin', len(non_updatable_plugins))} "
            "cannot be auto-updated (installed from local file, URL, or artifact)."
        )

    if error_count > 0:
        ctx.exit(ExitCode.UNEXPECTED_ERROR)


def _check_github_release_update(github_repo: str) -> Optional[Dict[str, Any]]:
    """
    Check for the latest release of a GitHub repository.

    Args:
        github_repo: Repository in "owner/repo" format.

    Returns:
        Release data dict or None if check fails.
    """
    # Get GitHub token if available
    github_token = os.environ.get("GITHUB_TOKEN")

    headers: Dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    try:
        response = requests.get(
            f"https://api.github.com/repos/{github_repo}/releases/latest",
            headers=headers,
            timeout=10,
        )
        if response.status_code == 200:
            return response.json()
    except requests.RequestException:
        pass

    return None


def _find_wheel_asset(release: Dict[str, Any]) -> Optional[str]:
    """
    Find a compatible wheel asset in a GitHub release.

    Prefers platform-specific wheels over pure-python wheels.

    Args:
        release: GitHub release data.

    Returns:
        Download URL for the wheel or None.
    """
    from ggshield.core.plugin.platform import get_wheel_platform_tags

    compatible_tags = get_wheel_platform_tags()
    assets = release.get("assets", [])

    fallback_url = None
    for asset in assets:
        name = asset.get("name", "")
        if not name.endswith(".whl"):
            continue
        url = asset.get("browser_download_url")
        # Pure-python wheels are always compatible
        if "py3-none-any" in name or "none-any" in name:
            fallback_url = url
            continue
        # Check platform-specific compatibility
        for tag in compatible_tags:
            if tag in name:
                return url
    return fallback_url
