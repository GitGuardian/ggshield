"""
Test plugin implementation.
"""

import click

from ggshield.core.plugin.base import GGShieldPlugin, PluginMetadata
from ggshield.core.plugin.registry import PluginRegistry

from . import __version__


@click.command("test-scan")
@click.argument("file_path", required=False)
@click.option("--text", "-t", help="Text to scan instead of a file")
def test_scan_cmd(file_path: str | None = None, text: str | None = None) -> None:
    """
    Test scan command provided by the test plugin.

    This is a placeholder command to verify plugin commands work.
    """
    from ggshield.core import ui

    if text:
        ui.display_info(f"Would scan text: {text[:50]}...")
    elif file_path:
        ui.display_info(f"Would scan file: {file_path}")
    else:
        ui.display_error("Please provide a file path or --text option")


@click.command("test-info")
def test_info_cmd() -> None:
    """
    Show test plugin information.
    """
    from ggshield.core import ui

    ui.display_heading("Test Plugin Info")
    ui.display_info(f"  Version: {__version__}")
    ui.display_info("  Capabilities: COMMAND")
    ui.display_info("  This is a test plugin to verify the plugin system works.")


class TestPlugin(GGShieldPlugin):
    """
    Test plugin for ggshield.

    This plugin provides:
    - Two test commands: test-scan and test-info
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="testplugin",
            version=__version__,
            display_name="Test Plugin",
            description="A simple test plugin to verify the plugin system",
            min_ggshield_version="1.0.0",
        )

    def register(self, registry: PluginRegistry) -> None:
        """Register plugin capabilities."""
        # Register CLI commands
        registry.register_command(test_scan_cmd)
        registry.register_command(test_info_cmd)

    def on_load(self) -> None:
        """Called when plugin is loaded."""
        import logging

        logging.getLogger(__name__).info("Test plugin loaded!")

    def on_unload(self) -> None:
        """Called when plugin is unloaded."""
        import logging

        logging.getLogger(__name__).info("Test plugin unloaded!")
