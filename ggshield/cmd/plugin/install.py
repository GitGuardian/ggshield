"""
Plugin install command.
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


@click.command()
@click.argument("plugin_name")
@click.option(
    "--version",
    "version",
    default=None,
    help="Specific version to install (defaults to latest)",
)
@add_common_options()
@click.pass_context
def install_cmd(
    ctx: click.Context,
    plugin_name: str,
    version: Optional[str],
    **kwargs: Any,
) -> None:
    """
    Download and install a plugin from GitGuardian.

    Install a specific plugin:

        ggshield plugin install tokenscanner

    Install a specific version:

        ggshield plugin install tokenscanner --version 0.1.0

    Plugins are downloaded from GitGuardian and installed locally.
    Requires authentication with a GitGuardian account.
    """

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
        downloader.download_and_install(download_info, plugin_name)

        # Enable in config
        enterprise_config.enable_plugin(plugin_name, version=download_info.version)

        # Save config
        enterprise_config.save()

        ui.display_info(f"Installed {plugin_name} v{download_info.version}")

    except PluginNotAvailableError as e:
        ui.display_error(f"Failed to install {plugin_name}: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except DownloadError as e:
        ui.display_error(f"Failed to install {plugin_name}: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
    except Exception as e:
        ui.display_error(f"Failed to install {plugin_name}: {e}")
        ctx.exit(ExitCode.UNEXPECTED_ERROR)
