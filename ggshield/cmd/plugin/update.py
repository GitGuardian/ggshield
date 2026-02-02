"""
Plugin update command - updates installed plugins.
"""

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
)
from ggshield.core.plugin.downloader import DownloadError, PluginDownloader
from ggshield.core.plugin.loader import PluginLoader
from ggshield.core.text_utils import pluralize


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

    """
    if not plugin_name and not update_all and not check_only:
        ui.display_error("Please specify a plugin name, use --all, or use --check")
        ui.display_info("Usage: ggshield plugin update <plugin_name>")
        ui.display_info("       ggshield plugin update --all")
        ui.display_info("       ggshield plugin update --check")
        ctx.exit(ExitCode.USAGE_ERROR)

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

    # Get installed plugins
    enterprise_config = EnterpriseConfig.load()
    loader = PluginLoader(enterprise_config)
    downloader = PluginDownloader()

    installed_plugins = {p.name: p for p in loader.discover_plugins() if p.is_installed}
    available_plugins = {p.name: p for p in catalog.plugins if p.available}

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

    # Check for updates
    updates_available = []
    for name in plugins_to_process:
        installed = installed_plugins.get(name)
        available = available_plugins.get(name)

        if not installed or not available:
            continue

        installed_version = installed.version
        latest_version = available.latest_version

        if installed_version and latest_version and installed_version != latest_version:
            updates_available.append(
                {
                    "name": name,
                    "installed_version": installed_version,
                    "latest_version": latest_version,
                }
            )

    # Check-only mode
    if check_only:
        if updates_available:
            ui.display_heading("Updates Available")
            for update in updates_available:
                ui.display_info(
                    f"  {update['name']}: {update['installed_version']} -> {update['latest_version']}"
                )
            ui.display_info("")
            ui.display_info("Run 'ggshield plugin update --all' to update.")
        else:
            ui.display_info("All plugins are up to date.")
        return

    # Update mode
    if not updates_available:
        if plugin_name:
            ui.display_info(f"Plugin '{plugin_name}' is already up to date.")
        else:
            ui.display_info("All plugins are already up to date.")
        return

    success_count = 0
    error_count = 0

    for update in updates_available:
        name = update["name"]
        latest_version = update["latest_version"]

        ui.display_info(
            f"Updating {name}: {update['installed_version']} -> {latest_version}..."
        )

        try:
            # Get download info
            download_info = plugin_api_client.get_download_info(
                name, version=latest_version
            )

            # Download and install (overwrites existing)
            downloader.download_and_install(download_info, name)

            # Update config
            enterprise_config.enable_plugin(name, version=download_info.version)

            ui.display_info(f"  Updated {name} to v{download_info.version}")
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

    if error_count > 0:
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
