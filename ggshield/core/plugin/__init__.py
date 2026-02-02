"""Plugin system for ggshield."""

from ggshield.core.plugin.base import GGShieldPlugin, PluginMetadata
from ggshield.core.plugin.loader import PluginLoader
from ggshield.core.plugin.registry import PluginRegistry


__all__ = [
    "GGShieldPlugin",
    "PluginMetadata",
    "PluginLoader",
    "PluginRegistry",
]
