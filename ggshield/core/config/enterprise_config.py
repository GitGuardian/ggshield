"""
Enterprise configuration - plugin settings.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional


if TYPE_CHECKING:
    from ggshield.core.plugin.signature import SignatureVerificationMode

from ggshield.core.config.utils import load_yaml_dict, save_yaml_dict
from ggshield.core.dirs import get_config_dir


def get_enterprise_config_filepath() -> Path:
    """Get the path to the enterprise config file."""
    return get_config_dir() / "enterprise_config.yaml"


@dataclass
class PluginConfig:
    """Configuration for a single plugin."""

    enabled: bool = True
    version: Optional[str] = None
    auto_update: bool = True


@dataclass
class EnterpriseConfig:
    """Enterprise configuration stored in ~/.config/ggshield/enterprise_config.yaml"""

    plugins: Dict[str, PluginConfig] = field(default_factory=dict)
    plugin_signature_mode: str = "strict"

    @classmethod
    def load(cls) -> "EnterpriseConfig":
        """Load enterprise config from file."""
        config_path = get_enterprise_config_filepath()
        data = load_yaml_dict(config_path)

        if data is None:
            return cls()

        # Convert plugin configs from dict
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

        plugin_signature_mode = data.get("plugin_signature_mode", "strict")

        return cls(plugins=plugins, plugin_signature_mode=plugin_signature_mode)

    def save(self) -> None:
        """Save enterprise config to file."""
        config_path = get_enterprise_config_filepath()

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

        data["plugin_signature_mode"] = self.plugin_signature_mode

        # Remove None values for cleaner YAML
        for plugin_data in data["plugins"].values():
            if plugin_data["version"] is None:
                del plugin_data["version"]

        save_yaml_dict(data, config_path)

    def get_signature_mode(self) -> "SignatureVerificationMode":
        """Get the signature verification mode."""
        from ggshield.core.plugin.signature import SignatureVerificationMode

        try:
            return SignatureVerificationMode(self.plugin_signature_mode)
        except ValueError:
            return SignatureVerificationMode.STRICT

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
            self.plugins[plugin_name] = PluginConfig(enabled=False)
            return

        self.plugins[plugin_name].enabled = False

    def is_plugin_enabled(self, plugin_name: str) -> bool:
        """Check if a plugin is enabled."""
        plugin_config = self.plugins.get(plugin_name)
        # Default: enabled if not explicitly configured
        return plugin_config.enabled if plugin_config else True

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
