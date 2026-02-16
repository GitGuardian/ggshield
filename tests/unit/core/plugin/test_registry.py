"""Tests for plugin registry."""

import click

from ggshield.core.plugin.base import GGShieldPlugin, PluginMetadata
from ggshield.core.plugin.registry import PluginRegistry


@click.command("test-cmd")
def mock_command() -> None:
    """A mock command for testing."""
    pass


class MockPlugin(GGShieldPlugin):
    """A mock plugin for testing."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="mockplugin",
            version="1.0.0",
            display_name="Mock Plugin",
            description="A mock plugin for testing",
            min_ggshield_version="1.0.0",
        )

    def register(self, registry: PluginRegistry) -> None:
        registry.register_command(mock_command)


class TestPluginRegistry:
    """Tests for PluginRegistry."""

    def test_empty_registry(self) -> None:
        """Test that new registry is empty."""
        registry = PluginRegistry()

        assert registry.get_all_plugins() == {}
        assert registry.get_commands() == []

    def test_register_plugin(self) -> None:
        """Test registering a plugin."""
        registry = PluginRegistry()
        plugin = MockPlugin()

        registry.register_plugin(plugin)

        assert registry.get_plugin("mockplugin") is plugin
        assert "mockplugin" in registry.get_all_plugins()

    def test_register_command(self) -> None:
        """Test registering a command."""
        registry = PluginRegistry()

        registry.register_command(mock_command)

        assert mock_command in registry.get_commands()

    def test_get_nonexistent_plugin(self) -> None:
        """Test getting a plugin that doesn't exist."""
        registry = PluginRegistry()

        assert registry.get_plugin("nonexistent") is None
