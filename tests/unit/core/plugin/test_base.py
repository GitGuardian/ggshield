"""Tests for plugin base classes."""

from ggshield.core.plugin.base import GGShieldPlugin, PluginMetadata
from ggshield.core.plugin.registry import PluginRegistry


class MockPlugin(GGShieldPlugin):
    """A mock plugin for testing."""

    def __init__(self, name: str = "mockplugin", version: str = "1.0.0"):
        self._name = name
        self._version = version

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self._name,
            version=self._version,
            display_name="Mock Plugin",
            description="A mock plugin for testing",
            min_ggshield_version="1.0.0",
        )

    def register(self, registry: PluginRegistry) -> None:
        pass


class TestPluginMetadata:
    """Tests for PluginMetadata dataclass."""

    def test_metadata_fields(self) -> None:
        """Test that metadata has expected fields."""
        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            display_name="Test",
            description="Test",
            min_ggshield_version="1.0.0",
        )

        assert metadata.name == "test"
        assert metadata.version == "1.0.0"


class TestGGShieldPlugin:
    """Tests for GGShieldPlugin ABC."""

    def test_plugin_lifecycle_hooks(self) -> None:
        """Test that lifecycle hooks have default implementations."""
        plugin = MockPlugin()
        # Should not raise
        plugin.on_load()
        plugin.on_unload()
