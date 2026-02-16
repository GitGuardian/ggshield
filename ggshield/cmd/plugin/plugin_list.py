"""
Plugin list command.
"""

from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.core import ui
from ggshield.core.config.enterprise_config import EnterpriseConfig
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

        # Version
        if plugin.version:
            status_parts.append(f"v{plugin.version}")

        # Enabled/disabled
        if plugin.is_enabled:
            status_parts.append("enabled")
        else:
            status_parts.append("disabled")

        # Source
        if plugin.wheel_path:
            status_parts.append("local")
        elif plugin.entry_point:
            status_parts.append("pip")

        status = ", ".join(status_parts)
        ui.display_info(f"  {plugin.name}: {status}")
