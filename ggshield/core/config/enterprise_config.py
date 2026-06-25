"""
Enterprise configuration - plugin settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from ggshield.core.config.utils import load_yaml_dict, save_yaml_dict
from ggshield.core.dirs import (
    create_world_traversable_dir,
    get_config_dir,
    get_system_config_dir,
    is_root,
    make_world_readable,
)


def get_enterprise_config_filepath(system: bool = False) -> Path:
    """Path to the enterprise config file (machine-wide when ``system``)."""
    base = get_system_config_dir() if system else get_config_dir()
    return base / "enterprise_config.yaml"


@dataclass
class PluginConfig:
    """Configuration for a single plugin."""

    enabled: bool = True
    version: Optional[str] = None
    auto_update: bool = True


@dataclass
class EnterpriseConfig:
    """Plugin enablement, layered: a machine-wide file (written by a root
    install) under each user's own file. Auth lives elsewhere, so the whole
    config is safe to share machine-wide.
    """

    plugins: Dict[str, PluginConfig] = field(default_factory=dict)

    @staticmethod
    def _load_plugins(config_path: Path) -> Dict[str, PluginConfig]:
        data = load_yaml_dict(config_path)
        if data is None:
            return {}
        plugins: Dict[str, PluginConfig] = {}
        for name, plugin_data in data.get("plugins", {}).items():
            if isinstance(plugin_data, dict):
                plugins[name] = PluginConfig(
                    enabled=plugin_data.get("enabled", True),
                    version=plugin_data.get("version"),
                    auto_update=plugin_data.get("auto_update", True),
                )
            elif isinstance(plugin_data, bool):
                # Simple format: just enabled/disabled
                plugins[name] = PluginConfig(enabled=plugin_data)
            else:
                plugins[name] = PluginConfig(enabled=True)
        return plugins

    @classmethod
    def load(cls) -> EnterpriseConfig:
        """Load the single file this process reads and writes: the machine-wide
        file when running as root, else the per-user file. ``install``/``enable``/
        ``disable`` mutate this and ``save()`` writes it back to the same file, so
        a root install lands machine-wide and a user install stays per-user — no
        flag. Readers that must see *both* layers use :meth:`load_effective`."""
        return cls(plugins=cls._load_plugins(get_enterprise_config_filepath(is_root())))

    @classmethod
    def load_effective(cls) -> EnterpriseConfig:
        """Effective enablement seen at runtime: both files merged, read-only.
        Used when loading/listing plugins so a root-enabled plugin is visible to
        every user.

        Both layers are always merged; precedence depends on who is running, so
        the layer that ``load``/``save`` mutate for this user wins on conflict:

        - Non-root: the per-user file overlays the system file — a user's own
          entry (e.g. an opt-out of an admin-enabled plugin) wins.
        - Root: the system file overlays the per-user one — a fresh ``sudo
          ggshield plugin enable/disable`` is never shadowed by a stale
          ``/root/.config`` entry, while a pre-machine-wide root install whose
          enablement lives only per-user stays visible until migrated.
        """
        system = cls._load_plugins(get_enterprise_config_filepath(system=True))
        user = cls._load_plugins(get_enterprise_config_filepath(system=False))
        if is_root():
            plugins = {**user, **system}  # system wins for root
        else:
            plugins = {**system, **user}  # per-user wins for everyone else
        return cls(plugins=plugins)

    def save(self) -> None:
        """Save to the EUID-appropriate file (machine-wide as root, else per-user)."""
        config_path = get_enterprise_config_filepath(is_root())

        # Convert to dict for saving
        data: Dict[str, Any] = {
            "plugins": {
                name: {
                    "enabled": cfg.enabled,
                    "version": cfg.version,
                    "auto_update": cfg.auto_update,
                }
                for name, cfg in self.plugins.items()
            }
        }

        # Remove None values for cleaner YAML
        for plugin_data in data["plugins"].values():
            if plugin_data["version"] is None:
                del plugin_data["version"]

        if is_root():
            # Pre-create the config dir chain world-traversable before writing:
            # save_yaml_dict's mkdir would otherwise leave it (and any nested
            # ancestors) owner-only under root's umask, hiding a world-readable
            # file from non-root readers.
            create_world_traversable_dir(config_path.parent)

        save_yaml_dict(data, config_path)

        if is_root():
            # Machine-wide enablement must be readable by every user, regardless
            # of root's umask — it holds only plugin names, nothing sensitive.
            make_world_readable(config_path)

    def enable_plugin(self, plugin_name: str, version: Optional[str] = None) -> None:
        """Enable a plugin."""
        if plugin_name not in self.plugins:
            self.plugins[plugin_name] = PluginConfig()

        self.plugins[plugin_name].enabled = True
        if version:
            self.plugins[plugin_name].version = version

    def disable_plugin(self, plugin_name: str) -> None:
        """Disable a plugin."""
        if plugin_name not in self.plugins:
            raise ValueError(f"Plugin '{plugin_name}' is not configured")

        self.plugins[plugin_name].enabled = False

    def is_plugin_enabled(self, plugin_name: str) -> bool:
        """Check if a plugin is enabled."""
        plugin_config = self.plugins.get(plugin_name)
        # Default: disabled if not explicitly configured
        return plugin_config.enabled if plugin_config else False

    def get_plugin_version(self, plugin_name: str) -> Optional[str]:
        """Get the configured version of a plugin."""
        plugin_config = self.plugins.get(plugin_name)
        return plugin_config.version if plugin_config else None

    def remove_plugin(self, plugin_name: str) -> bool:
        """Remove a plugin from configuration."""
        if plugin_name in self.plugins:
            del self.plugins[plugin_name]
            return True
        return False
