"""
Base classes for ggshield plugins.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from ggshield.core.plugin.registry import PluginRegistry


@dataclass
class PluginMetadata:
    """Metadata about a plugin."""

    name: str
    version: str
    display_name: str
    description: str
    min_ggshield_version: str


class GGShieldPlugin(ABC):
    """Abstract base class for all ggshield plugins."""

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        pass

    @abstractmethod
    def register(self, registry: "PluginRegistry") -> None:
        """Register plugin capabilities with the registry."""
        pass

    def on_load(self) -> None:
        """Called after the plugin is loaded."""
        pass

    def on_unload(self) -> None:
        """Called before the plugin is unloaded."""
        pass
