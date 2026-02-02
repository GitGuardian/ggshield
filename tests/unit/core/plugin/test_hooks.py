"""Tests for plugin hooks."""

from ggshield.core.plugin.hooks import get_plugin_registry, set_plugin_registry
from ggshield.core.plugin.registry import PluginRegistry


class TestPluginHooks:
    """Tests for plugin hooks."""

    def test_set_and_get_registry(self) -> None:
        """Test setting and getting the global registry."""
        registry = PluginRegistry()
        set_plugin_registry(registry)

        result = get_plugin_registry()
        assert result is registry

    def test_get_registry_before_set(self) -> None:
        """Test getting registry before it's set returns None."""
        # Reset the global state
        set_plugin_registry(None)  # type: ignore[arg-type]

        result = get_plugin_registry()
        assert result is None
