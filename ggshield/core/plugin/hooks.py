"""
Plugin hooks - utilities for integrating plugins into existing commands.
"""

from typing import Optional

from ggshield.core.plugin.registry import PluginRegistry


_global_registry: Optional[PluginRegistry] = None


def set_plugin_registry(registry: PluginRegistry) -> None:
    """Set the global plugin registry."""
    global _global_registry
    _global_registry = registry


def get_plugin_registry() -> Optional[PluginRegistry]:
    """Get the global plugin registry."""
    return _global_registry
