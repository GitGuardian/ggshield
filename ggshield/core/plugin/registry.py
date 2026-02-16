"""
Plugin registry - central registry for all loaded plugins and their capabilities.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import click

from ggshield.core.plugin.base import GGShieldPlugin


@dataclass
class PluginRegistry:
    """Central registry for all loaded plugins and their capabilities."""

    _plugins: Dict[str, GGShieldPlugin] = field(default_factory=dict)
    _commands: List[click.Command] = field(default_factory=list)

    def register_plugin(self, plugin: GGShieldPlugin) -> None:
        """Register a loaded plugin."""
        self._plugins[plugin.metadata.name] = plugin

    def register_command(self, command: click.Command) -> None:
        """Register a CLI command provided by a plugin."""
        self._commands.append(command)

    def get_plugin(self, name: str) -> Optional[GGShieldPlugin]:
        """Get a loaded plugin by name."""
        return self._plugins.get(name)

    def get_all_plugins(self) -> Dict[str, GGShieldPlugin]:
        """Get all loaded plugins."""
        return self._plugins.copy()

    def get_commands(self) -> List[click.Command]:
        """Get all plugin-provided commands."""
        return self._commands.copy()
