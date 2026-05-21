"""
Plugin list command.
"""

from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.core import ui
from ggshield.core.config.enterprise_config import EnterpriseConfig
from ggshield.core.plugin.downloader import PluginDownloader
from ggshield.core.plugin.loader import PluginLoader


@click.command("list")
@add_common_options()
@click.pass_context
def list_cmd(ctx: click.Context, **kwargs: Any) -> None:
    """
    List installed plugins.

    Shows all plugins that are currently installed on your system,
    along with their version and enabled/disabled status.

    Use 'ggshield plugin status' to see available plugins
    that can be installed.
    """
    enterprise_config = EnterpriseConfig.load()
    loader = PluginLoader(enterprise_config)
    downloader = PluginDownloader()

    discovered = loader.discover_plugins()

    if not discovered:
        ui.display_info("No plugins installed.")
        ui.display_info("")
        ui.display_info("To see available plugins:")
        ui.display_info("  ggshield plugin status")
        ui.display_info("")
        ui.display_info("To install a plugin:")
        ui.display_info("  ggshield plugin install <plugin_name>")
        return

    ui.display_heading("Installed Plugins")

    for plugin in discovered:
        status_parts = []

        if plugin.version:
            status_parts.append(f"v{plugin.version}")

        if plugin.is_enabled:
            status_parts.append("enabled")
        else:
            status_parts.append("disabled")

        source = (
            downloader.get_plugin_source(plugin.name) if plugin.wheel_path else None
        )
        if source is not None:
            status_parts.append(source.type.value.replace("_", " "))
        elif plugin.entry_point:
            status_parts.append("pip")
        elif plugin.wheel_path:
            status_parts.append("on-disk")

        sig_label = downloader.get_installed_signature_label(plugin.name)
        if sig_label:
            status_parts.append(f"signature: {sig_label}")

        status = ", ".join(status_parts)
        ui.display_info(f"  {plugin.name}: {status}")
