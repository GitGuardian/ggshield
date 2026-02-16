"""
Plugin management commands (enable/disable/uninstall).
"""

from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.core import ui
from ggshield.core.config.enterprise_config import EnterpriseConfig
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.downloader import PluginDownloader


@click.command()
@click.argument("plugin_name")
@add_common_options()
@click.pass_context
def enable_cmd(ctx: click.Context, plugin_name: str, **kwargs: Any) -> None:
    """
    Enable an installed plugin.

    Enabled plugins are loaded when ggshield starts and their
    features become available.

    Example:

        ggshield plugin enable tokenscanner
    """
    enterprise_config = EnterpriseConfig.load()
    downloader = PluginDownloader()

    # Check if plugin is installed
    if not downloader.is_installed(plugin_name):
        # Check if it's available via entry point
        from ggshield.core.plugin.loader import PluginLoader

        loader = PluginLoader(enterprise_config)
        discovered = {p.name: p for p in loader.discover_plugins()}

        if plugin_name not in discovered:
            ui.display_error(f"Plugin '{plugin_name}' is not installed")
            ui.display_info("Use 'ggshield plugin install' to install it first")
            ctx.exit(ExitCode.USAGE_ERROR)

    enterprise_config.enable_plugin(plugin_name)
    enterprise_config.save()

    ui.display_info(f"Enabled plugin: {plugin_name}")


@click.command()
@click.argument("plugin_name")
@add_common_options()
@click.pass_context
def disable_cmd(ctx: click.Context, plugin_name: str, **kwargs: Any) -> None:
    """
    Disable a plugin without uninstalling.

    Disabled plugins remain installed but are not loaded when
    ggshield starts. Their features become unavailable.

    Example:

        ggshield plugin disable tokenscanner
    """
    enterprise_config = EnterpriseConfig.load()

    try:
        enterprise_config.disable_plugin(plugin_name)
    except ValueError as e:
        ui.display_error(str(e))
        ui.display_info("Use 'ggshield plugin list' to see configured plugins")
        ctx.exit(ExitCode.USAGE_ERROR)

    enterprise_config.save()

    ui.display_info(f"Disabled plugin: {plugin_name}")


@click.command()
@click.argument("plugin_name")
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip confirmation prompt",
)
@add_common_options()
@click.pass_context
def uninstall_cmd(
    ctx: click.Context, plugin_name: str, yes: bool, **kwargs: Any
) -> None:
    """
    Remove an installed plugin.

    This removes the plugin files from your system. You can
    reinstall it later with 'ggshield plugin install'.

    Example:

        ggshield plugin uninstall tokenscanner
    """
    downloader = PluginDownloader()

    # Check if installed via manifest (wheel/artifact)
    if downloader.is_installed(plugin_name):
        # Confirm
        if not yes:
            click.confirm(
                f"Uninstall plugin '{plugin_name}'?",
                abort=True,
            )

        # Uninstall
        if downloader.uninstall(plugin_name):
            # Remove from config
            enterprise_config = EnterpriseConfig.load()
            enterprise_config.remove_plugin(plugin_name)
            enterprise_config.save()

            ui.display_info(f"Uninstalled plugin: {plugin_name}")
        else:
            ui.display_error(f"Failed to uninstall plugin: {plugin_name}")
            ctx.exit(ExitCode.UNEXPECTED_ERROR)
        return

    # Check if it's an entry-point plugin
    from ggshield.core.plugin.loader import PluginLoader

    loader = PluginLoader(EnterpriseConfig.load())
    discovered = {p.name: p for p in loader.discover_plugins()}

    if plugin_name in discovered:
        ep = discovered[plugin_name].entry_point
        if ep is not None:
            # Entry point format: "plugin_name = module:attr" - get the distribution name
            dist_name: str | None = None
            try:
                dist = getattr(ep, "dist", None)
                if dist is not None:
                    dist_name = dist.name
            except Exception:
                pass

            ui.display_error(
                f"Plugin '{plugin_name}' was installed via pip, not ggshield."
            )
            if dist_name:
                ui.display_info(f"To uninstall, run: pip uninstall {dist_name}")
            else:
                ui.display_info(
                    "To uninstall, use pip uninstall with the package name."
                )
            ctx.exit(ExitCode.USAGE_ERROR)

    # Not found anywhere
    ui.display_error(f"Plugin '{plugin_name}' is not installed")
    ctx.exit(ExitCode.USAGE_ERROR)
