"""
Plugin status command.
"""

from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.config.enterprise_config import EnterpriseConfig
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.client import PluginAPIClient, PluginAPIError
from ggshield.core.plugin.downloader import PluginDownloader


@click.command()
@add_common_options()
@click.pass_context
def status_cmd(ctx: click.Context, **kwargs: Any) -> None:
    """
    Show available plugins for your GitGuardian account.

    Displays your account's plan, available plugins, and feature flags.
    Requires authentication with GitGuardian.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config

    try:
        client = create_client_from_config(config)
        plugin_api_client = PluginAPIClient(client)
        catalog = plugin_api_client.get_available_plugins()
    except PluginAPIError as e:
        ui.display_error(str(e))
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except Exception as e:
        ui.display_error(f"Failed to fetch plugin catalog: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)

    # Load local config for installed plugins info
    enterprise_config = EnterpriseConfig.load()
    downloader = PluginDownloader()

    # Display plan
    ui.display_heading("Account Status")
    ui.display_info(f"Plan: {catalog.plan}")

    # Display features
    if catalog.features:
        ui.display_heading("Features")
        for feature, enabled in sorted(catalog.features.items()):
            status = "enabled" if enabled else "disabled"
            icon = "+" if enabled else "-"
            ui.display_info(f"  [{icon}] {feature}: {status}")

    # Display available plugins
    ui.display_heading("Available Plugins")
    for plugin in catalog.plugins:
        installed_version = downloader.get_installed_version(plugin.name)
        is_enabled = enterprise_config.is_plugin_enabled(plugin.name)

        if plugin.available:
            status_parts = []
            if installed_version:
                status_parts.append(f"installed v{installed_version}")
                if is_enabled:
                    status_parts.append("enabled")
                else:
                    status_parts.append("disabled")
                # Check for updates
                if plugin.latest_version and installed_version != plugin.latest_version:
                    status_parts.append(f"update available: v{plugin.latest_version}")
            else:
                status_parts.append(f"available v{plugin.latest_version}")

            status_str = ", ".join(status_parts)
            ui.display_info(f"  {plugin.display_name} ({plugin.name})")
            ui.display_info(f"    Status: {status_str}")
            ui.display_info(f"    {plugin.description}")
        else:
            ui.display_info(f"  {plugin.display_name} ({plugin.name}) - not available")
            if plugin.reason:
                ui.display_info(f"    Reason: {plugin.reason}")
