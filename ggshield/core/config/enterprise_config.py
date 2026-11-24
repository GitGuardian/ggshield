"""
Enterprise configuration - plugin settings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ggshield.core.config.utils import load_yaml_dict, save_yaml_dict
from ggshield.core.dirs import (
    create_world_traversable_dir,
    get_config_dir,
    get_system_config_dir,
    get_system_config_dirs,
    is_root,
    is_safe_system_path,
    make_world_readable,
)


logger = logging.getLogger(__name__)


def get_enterprise_config_filepath(system: bool = False) -> Path:
    """Path to the enterprise config file (machine-wide when ``system``)."""
    base = get_system_config_dir() if system else get_config_dir()
    return base / "enterprise_config.yaml"


def get_system_enterprise_config_filepaths() -> List[Path]:
    """Machine-wide enterprise config paths in precedence order."""
    return [d / "enterprise_config.yaml" for d in get_system_config_dirs()]


def _is_valid_plugin_entry(plugin_data: Any) -> bool:
    """Reject values such as ``enabled: "false"`` that would read as truthy."""
    if isinstance(plugin_data, bool):
        return True
    if not isinstance(plugin_data, dict):
        return False
    return (
        isinstance(plugin_data.get("enabled", True), bool)
        and isinstance(plugin_data.get("auto_update", True), bool)
        and isinstance(plugin_data.get("version"), (str, type(None)))
    )


@dataclass
class PluginConfig:
    """Configuration for a single plugin.

    ``version`` and ``auto_update`` are recorded at install time but are not
    enforced: nothing pins the plugin to ``version`` and ``plugin update``
    ignores ``auto_update``.
    """

    enabled: bool = True
    version: Optional[str] = None
    auto_update: bool = True


@dataclass
class EnterpriseConfigSource:
    """One enterprise config file read by :meth:`EnterpriseConfig.load_effective`."""

    path: Path
    scope: str  # "system" or "user"
    exists: bool
    plugins: Dict[str, PluginConfig] = field(default_factory=dict)
    error: Optional[Exception] = None
    # Set when the file may exist but cannot be checked (e.g. an unsearchable
    # parent); load_effective() then treats it as absent.
    inaccessible: Optional[OSError] = None
    # Why load_effective() skips an XDG_CONFIG_DIRS file (unsafe or invalid).
    ignored: Optional[str] = None


@dataclass
class EnterpriseConfig:
    """Plugin enablement, layered: a machine-wide file (written by a root
    install) under each user's own file. Auth lives elsewhere, so the whole
    config is safe to share machine-wide.
    """

    plugins: Dict[str, PluginConfig] = field(default_factory=dict)

    @staticmethod
    def _load_plugins(
        config_path: Path, *, strict_mapping: bool = False
    ) -> Dict[str, PluginConfig]:
        data = load_yaml_dict(config_path, strict_mapping=strict_mapping)
        if data is None:
            return {}
        plugin_entries = data.get("plugins", {})
        if not isinstance(plugin_entries, dict):
            raise ValueError(f"{config_path}: 'plugins' should be a dictionary.")
        plugins: Dict[str, PluginConfig] = {}
        for name, plugin_data in plugin_entries.items():
            if strict_mapping and not _is_valid_plugin_entry(plugin_data):
                raise ValueError(f"{config_path}: invalid entry for plugin {name!r}.")
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
        """Merge system and user plugin settings for discovery.

        The fixed system file wins among system files. The system layer wins for
        root, while the per-user file wins for everyone else.
        """
        return cls.from_sources(cls.effective_sources(strict=True))

    @classmethod
    def effective_sources(cls, *, strict: bool = False) -> List[EnterpriseConfigSource]:
        """Files merged by :meth:`load_effective`, lowest precedence first
        (later wins). Strict reads stop at the first error in the fixed system
        or user file; a broken ``XDG_CONFIG_DIRS`` file is only ignored."""
        fixed, *secondary = get_system_enterprise_config_filepaths()
        system = [cls._read_secondary_source(path) for path in reversed(secondary)]
        system.append(cls._read_source(fixed, "system", strict))
        user = cls._read_source(
            get_enterprise_config_filepath(system=False), "user", strict
        )
        if is_root():
            return [user, *system]  # system wins for root
        return [*system, user]

    @classmethod
    def _read_source(
        cls, path: Path, scope: str, strict: bool
    ) -> EnterpriseConfigSource:
        source = EnterpriseConfigSource(path=path, scope=scope, exists=False)
        try:
            source.exists = path.exists()
            if not source.exists and not strict:
                try:
                    path.stat()
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    source.inaccessible = exc
            source.plugins = cls._load_plugins(path)
        except Exception as exc:
            if strict:
                raise
            source.error = exc
        return source

    @classmethod
    def _read_secondary_source(cls, path: Path) -> EnterpriseConfigSource:
        source = EnterpriseConfigSource(
            path=path, scope="system, XDG_CONFIG_DIRS", exists=False
        )
        try:
            path.lstat()
        except FileNotFoundError:
            return source
        except OSError as exc:
            source.ignored = f"cannot access: {exc}"
            return source
        source.exists = True
        if not is_safe_system_path(path):
            source.ignored = "not a regular file owned by root, or writable by others"
            return source
        try:
            source.plugins = cls._load_plugins(path, strict_mapping=True)
        except (OSError, ValueError, yaml.YAMLError) as e:
            logger.debug("Cannot load secondary enterprise config %s: %s", path, e)
            source.ignored = f"invalid: {e}"
        return source

    @classmethod
    def from_sources(cls, sources: List[EnterpriseConfigSource]) -> EnterpriseConfig:
        """Merge readable sources, lowest precedence first."""
        plugins: Dict[str, PluginConfig] = {}
        for source in sources:
            plugins.update(source.plugins)
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
